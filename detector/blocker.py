"""
blocker.py -- iptables-based IP Blocking

Manages a runtime ban list and drives iptables INSERT / DELETE operations
through asyncio subprocesses so the event loop is never blocked.
"""

import asyncio
import ipaddress
import logging
import time

logger = logging.getLogger(__name__)


class Blocker:
    """
    Manages iptables bans for anomalous IPs.

    All iptables calls are made via asyncio.create_subprocess_exec so the
    calling coroutine is suspended (not blocked) while the kernel processes
    the rule change.
    """

    def __init__(self, config: dict) -> None:
        # Whether the blocker is permitted to modify iptables at all.
        # When False every ban/unban call is a safe no-op.
        self._enabled: bool = bool(config.get("enabled", False))

        # In-memory registry of currently banned IPs.
        # Schema: { ip: {"banned_at": float, "offense_count": int, "duration": int | None} }
        self._banned: dict[str, dict] = {}

    # ---------------------------------------------------------------------- #
    # Public API                                                               #
    # ---------------------------------------------------------------------- #

    async def ban(self, ip: str, duration_seconds: int | None) -> bool:
        """
        Insert a DROP rule for *ip* into the INPUT chain.

        Parameters
        ----------
        ip              : IPv4/IPv6 address string
        duration_seconds: seconds until the ban should be lifted, or None for
                          a permanent ban (caller is responsible for unbanning)

        Returns True on success, False when blocking is disabled or the
        iptables call fails.
        """
        # ------------------------------------------------------------------ #
        # 1. Guard: do nothing when the blocker is disabled.                  #
        # ------------------------------------------------------------------ #
        if not self._enabled:
            logger.debug("Blocker disabled -- skipping ban for %s", ip)
            return False

        # ------------------------------------------------------------------ #
        # 2. Validate the IP address before touching iptables.                #
        # ------------------------------------------------------------------ #
        if not ip or ip.lower() == "unknown":
            logger.warning("ban() called with invalid IP %r -- skipping", ip)
            return False

        if self._is_private_ip(ip):
            logger.debug("Skipping ban for private/loopback IP %s", ip)
            return False

        # ------------------------------------------------------------------ #
        # 3. Run: iptables -I INPUT -s <ip> -j DROP                          #
        #    We use -I (insert at position 1) rather than -A (append) so the  #
        #    DROP rule takes precedence over any later ACCEPT rules.           #
        # ------------------------------------------------------------------ #
        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        logger.info("Banning IP %s: %s", ip, " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(
                    "iptables ban failed for %s (rc=%d): stdout=%r stderr=%r",
                    ip,
                    proc.returncode,
                    stdout.decode(errors="replace"),
                    stderr.decode(errors="replace"),
                )
                return False

        except Exception:
            logger.exception("Unexpected error while banning IP %s", ip)
            return False

        # ------------------------------------------------------------------ #
        # 4. Record the ban in the in-memory registry.                        #
        #    Increment offense_count if the IP was previously known.          #
        # ------------------------------------------------------------------ #
        existing = self._banned.get(ip, {})
        self._banned[ip] = {
            "banned_at": time.time(),
            "offense_count": existing.get("offense_count", 0) + 1,
            "duration": duration_seconds,
        }

        logger.info(
            "IP %s banned (offense #%d, duration=%s)",
            ip,
            self._banned[ip]["offense_count"],
            f"{duration_seconds}s" if duration_seconds is not None else "permanent",
        )
        return True

    async def unban(self, ip: str) -> bool:
        """
        Delete the DROP rule for *ip* from the INPUT chain.

        The in-memory registry entry is removed ONLY when iptables succeeds,
        so stale entries are kept if the kernel rejects the delete.

        Returns True on success, False otherwise.
        """
        if not self._enabled:
            logger.debug("Blocker disabled -- skipping unban for %s", ip)
            return False

        # ------------------------------------------------------------------ #
        # Run: iptables -D INPUT -s <ip> -j DROP                              #
        # ------------------------------------------------------------------ #
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        logger.info("Unbanning IP %s: %s", ip, " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(
                    "iptables unban failed for %s (rc=%d): stdout=%r stderr=%r",
                    ip,
                    proc.returncode,
                    stdout.decode(errors="replace"),
                    stderr.decode(errors="replace"),
                )
                return False

        except Exception:
            logger.exception("Unexpected error while unbanning IP %s", ip)
            return False

        # ------------------------------------------------------------------ #
        # Remove from registry only after the kernel confirms the deletion.   #
        # ------------------------------------------------------------------ #
        self._banned.pop(ip, None)
        logger.info("IP %s unbanned successfully", ip)
        return True

    def is_banned(self, ip: str) -> bool:
        """Return True if *ip* is currently in the ban registry."""
        return ip in self._banned

    def get_offense_count(self, ip: str) -> int:
        """Return the number of times *ip* has been banned (0 if never)."""
        return self._banned.get(ip, {}).get("offense_count", 0)

    def get_banned_ips(self) -> dict:
        """Return a shallow copy of the current ban registry."""
        return dict(self._banned)

    async def get_current_rules(self) -> list[str]:
        """
        Query iptables for all DROP rules currently active on the INPUT chain.

        Returns a list of rule-line strings (one per matching line) as
        reported by `iptables -L INPUT -n`.  Returns an empty list on error.
        """
        cmd = ["iptables", "-L", "INPUT", "-n"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(
                    "iptables list failed (rc=%d): %r",
                    proc.returncode,
                    stderr.decode(errors="replace"),
                )
                return []

            lines = stdout.decode(errors="replace").splitlines()
            # Keep only lines that mention a DROP target.
            return [line for line in lines if "DROP" in line]

        except Exception:
            logger.exception("Unexpected error while listing iptables rules")
            return []

    # ---------------------------------------------------------------------- #
    # Private helpers                                                          #
    # ---------------------------------------------------------------------- #

    def _is_private_ip(self, ip: str) -> bool:
        """
        Return True when *ip* is a private, loopback, or link-local address
        that should never be blocked via iptables.

        Covers RFC 1918 (10/8, 172.16/12, 192.168/16), loopback (127/8,
        ::1), and link-local (169.254/16, fe80::/10).
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Un-parseable string -- treat as invalid, not private.
            logger.debug("_is_private_ip: could not parse %r", ip)
            return False

        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
        )
