"""Opt-in response actions for confirmed attacks.

Blocking is never automatic: the UI asks for confirmation, then this module
adds a single Windows Firewall rule for the offending source address. Keeping
the firewall calls out of the UI makes them easy to test and easy to replace
with another response mechanism later.
"""

import ctypes
import ipaddress
import os
import socket
import subprocess

RULE_PREFIX = "SnifferBlock-"
_CREATE_NO_WINDOW = 0x08000000


class ResponseError(RuntimeError):
    """Raised when a firewall action cannot be completed."""


def is_valid_ip(address: str) -> bool:
    try:
        ipaddress.ip_address((address or "").strip())
    except ValueError:
        return False
    return True


def is_admin() -> bool:
    """True when this process can change Windows Firewall rules."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_protected(address: str) -> bool:
    """Refuse to block addresses this computer needs to stay online."""
    return address.strip() in protected_ips()


def protected_ips() -> set:
    """Loopback, the default gateway, this host's addresses, and DNS servers."""
    addresses = {"127.0.0.1", "::1"}

    try:
        from scapy.all import conf

        gateway = conf.route.route("0.0.0.0")[2]
        if gateway and gateway not in {"0.0.0.0", "::", ""}:
            addresses.add(gateway)
    except Exception:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            address = info[4][0]
            # IPv6 link-local addresses carry a "%zone" suffix.
            addresses.add(address.split("%")[0])
    except Exception:
        pass

    addresses.update(_dns_servers())
    return {address for address in addresses if is_valid_ip(address)}


def _dns_servers() -> set:
    if os.name != "nt":
        return set()
    servers = set()
    try:
        import winreg

        path = (
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        )
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as interfaces:
            index = 0
            while True:
                try:
                    interface_name = winreg.EnumKey(interfaces, index)
                except OSError:
                    break
                index += 1
                with winreg.OpenKey(interfaces, interface_name) as interface:
                    for value_name in ("NameServer", "DhcpNameServer"):
                        try:
                            value, _ = winreg.QueryValueEx(
                                interface, value_name
                            )
                        except OSError:
                            continue
                        servers.update(
                            part
                            for part in value.replace(",", " ").split()
                            if part
                        )
    except Exception:
        pass
    return servers


def rule_name(address: str) -> str:
    # No spaces: netsh treats spaces as argument separators.
    return f"{RULE_PREFIX}{address}"


def is_blocked(address: str) -> bool:
    _require_windows()
    address = _normalised(address)
    result = _run(
        ["netsh", "advfirewall", "firewall", "show", "rule",
         f"name={rule_name(address)}"]
    )
    return result.returncode == 0


def block_source(address: str) -> None:
    """Add an inbound firewall rule that drops traffic from `address`."""
    address = _normalised(address)
    _require_windows()
    _require_admin()

    result = _run(
        ["netsh", "advfirewall", "firewall", "add", "rule",
         f"name={rule_name(address)}", "dir=in", "action=block",
         f"remoteip={address}"]
    )
    if result.returncode != 0:
        raise ResponseError(_output(result) or "Could not add the firewall rule.")


def unblock_source(address: str) -> None:
    """Remove the firewall rule created by `block_source`."""
    address = _normalised(address)
    _require_windows()
    _require_admin()

    result = _run(
        ["netsh", "advfirewall", "firewall", "delete", "rule",
         f"name={rule_name(address)}"]
    )
    if result.returncode != 0:
        raise ResponseError(
            _output(result) or "Could not remove the firewall rule."
        )


# ----------------------------------------------------------------------


def _normalised(address: str) -> str:
    try:
        return str(ipaddress.ip_address((address or "").strip()))
    except ValueError:
        raise ResponseError(f'"{address}" is not a valid IP address.')


def _require_windows() -> None:
    if os.name != "nt":
        raise ResponseError("Firewall blocking is only supported on Windows.")


def _require_admin() -> None:
    if not is_admin():
        raise ResponseError(
            "Administrator rights are required. Close the app, reopen it as "
            "administrator, and try again."
        )


def _run(args):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        errors="replace",
        creationflags=_CREATE_NO_WINDOW if os.name == "nt" else 0,
    )


def _output(result) -> str:
    return (result.stdout or result.stderr or "").strip()
