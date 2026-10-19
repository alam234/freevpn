"""Run and control an OpenVPN client process."""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

CREATE_NO_WINDOW = 0x08000000


def is_admin() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def relaunch_as_admin() -> bool:
    """Ask Windows (UAC) to restart this app elevated. Returns True if the
    elevated copy was started."""
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in [script, *sys.argv[1:]])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    return rc > 32


def find_openvpn() -> str | None:
    candidates = []
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\OpenVPN") as k:
                exe = winreg.QueryValueEx(k, "exe_path")[0]
                candidates.append(exe)
        except OSError:
            pass
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            candidates.append(os.path.join(base, "OpenVPN", "bin", "openvpn.exe"))
    on_path = shutil.which("openvpn")
    if on_path:
        candidates.append(on_path)
    return next((c for c in candidates if c and os.path.isfile(c)), None)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


ADAPTER_NAME = "FreeVPN"


def ensure_adapter(openvpn_exe: str, log: Callable[[str], None]) -> str | None:
    """Make sure a TAP adapter named FreeVPN exists (needs admin). VPN Gate
    servers only speak AES-128-CBC, which the DCO driver can't carry, so
    OpenVPN needs a TAP adapter; a dedicated one avoids borrowing another
    VPN product's adapter. Returns the adapter name, or None to let OpenVPN
    pick any free one."""
    tapctl = os.path.join(os.path.dirname(openvpn_exe), "tapctl.exe")
    if os.name != "nt" or not os.path.isfile(tapctl):
        return None
    flags = CREATE_NO_WINDOW
    try:
        # e.g.  'FreeVPN' {5C3734E2-...} tap-windows6
        out = subprocess.run([openvpn_exe, "--show-adapters"], capture_output=True, text=True,
                             timeout=30, creationflags=flags).stdout
        if re.search(rf"^'{ADAPTER_NAME}' \{{.*\}} tap-windows6", out, re.M):
            return ADAPTER_NAME
        r = subprocess.run([tapctl, "create", "--name", ADAPTER_NAME, "--hwid", "root\\tap0901"],
                           capture_output=True, text=True, timeout=60, creationflags=flags)
        msg = (r.stderr or r.stdout).strip()
        if r.returncode == 0 or "already exists" in msg:
            if r.returncode == 0:
                log(f"Created network adapter '{ADAPTER_NAME}'")
            return ADAPTER_NAME
        log(f"Couldn't create TAP adapter ({msg}); "
            "letting OpenVPN pick one")
    except (OSError, subprocess.SubprocessError) as e:
        log(f"tapctl failed: {e}")
    return None


def clear_stale_routes(adapter: str, log: Callable[[str], None]) -> None:
    """Remove default-route halves left on our own adapter by a session that
    was killed before OpenVPN could clean up (needs admin)."""
    ps = (f"Get-NetRoute -InterfaceAlias '{adapter}' -ErrorAction SilentlyContinue | "
          "Where-Object { $_.DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1','::/1',"
          "'8000::/1' } | Remove-NetRoute -Confirm:$false "
          "-ErrorAction SilentlyContinue")
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True,
                       timeout=30, creationflags=CREATE_NO_WINDOW)
    except (OSError, subprocess.SubprocessError) as e:
        log(f"Couldn't clear old routes: {e}")


IPV6_BLOCK_PREFIXES = ("::/1", "8000::/1")


IPV6_BLOCK_ADDRESS = "fd00:f4ee:7e9::2"


def set_ipv6_block(adapter: str, enable: bool, log: Callable[[str], None]) -> None:
    """VPN Gate is IPv4-only, so without this the PC's real IPv6 address
    keeps working around the tunnel. Give the VPN adapter a private IPv6
    address and point all IPv6 at it: Windows then sends IPv6 into the
    tunnel (where OpenVPN's block-ipv6 rejects it at once) instead of out of
    Wi-Fi, and ranks IPv6 below IPv4 so apps use IPv4 through the VPN.
    The address matters: with routes alone Windows picks the Wi-Fi address
    as source, and that pins the packet to Wi-Fi regardless of routes.
    Done by the app after the tunnel is up, because OpenVPN doing it
    mid-handshake (netsh) can stall past the server's keepalive on some PCs."""
    cmds = [["netsh", "interface", "ipv6", "add" if enable else "delete", "address",
             f"interface={adapter}", f"address={IPV6_BLOCK_ADDRESS}"]
            + (["store=active"] if enable else [])]
    for prefix in IPV6_BLOCK_PREFIXES:
        cmd = ["netsh", "interface", "ipv6", "add" if enable else "delete", "route", prefix,
               f"interface={adapter}"]
        if enable:
            cmd += ["metric=1", "store=active"]
        cmds.append(cmd)
    if not enable:
        cmds.reverse()
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                               creationflags=CREATE_NO_WINDOW)
            if enable and r.returncode != 0 and "exists" not in r.stdout:
                log(f"IPv6 block step failed ({' '.join(cmd[3:6])}): {r.stdout.strip()}")
        except (OSError, subprocess.SubprocessError) as e:
            log(f"IPv6 block step failed: {e}")
    if enable:
        log("IPv6 blocked while connected (VPN Gate servers are IPv4-only)")


IPV6_STATE_FILE = Path(__file__).resolve().parent / "logs" / "ipv6_routes_removed.txt"

# e.g. "No       Manual    16   ::/0      6  fe80::b4dc:40ff:fe30:9381"
_DEFAULT_ROUTE6 = re.compile(r"^\s*\S+\s+\S+\s+(\d+)\s+::/0\s+(\d+)\s+(\S.*?)\s*$", re.M)


def _netsh(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["netsh", "interface", "ipv6", *args], capture_output=True,
                          text=True, timeout=30, creationflags=CREATE_NO_WINDOW)


def disable_physical_ipv6(adapter: str, log: Callable[[str], None]) -> None:
    """Stop IPv6 leaving through Wi-Fi/Ethernet while connected. Routes into
    the tunnel aren't enough on Windows: it picks the Wi-Fi IPv6 address as
    source, which pins traffic to Wi-Fi's default route. So remove that
    default route and tell the interface to ignore new ones from the router;
    IPv6 then has no way out except the tunnel, where OpenVPN blocks it.
    Uses netsh (PowerShell's network cmdlets can take over a minute on PCs
    with many adapters) and only 'active' changes, which a reboot also
    undoes. What was removed is recorded so restore_physical_ipv6() can put
    it back, even after a crash."""
    try:
        routes = [m.groups() for m in _DEFAULT_ROUTE6.finditer(_netsh("show", "route").stdout)]
        if not routes:
            log("No IPv6 default route outside the VPN; nothing to block")
            return
        IPV6_STATE_FILE.parent.mkdir(exist_ok=True)
        IPV6_STATE_FILE.write_text("\n".join("|".join(r) for r in routes), encoding="utf-8")
        for metric, idx, gateway in routes:
            _netsh("set", "interface", f"interface={idx}", "ignoredefaultroutes=enabled",
                   "store=active")
            cmd = ["delete", "route", "::/0", f"interface={idx}"]
            if ":" in gateway:
                cmd.append(f"nexthop={gateway}")
            r = _netsh(*cmd, "store=active")
            if r.returncode != 0:
                log(f"Couldn't remove IPv6 default route on interface {idx}: {r.stdout.strip()}")
        left = [m.group(2) for m in _DEFAULT_ROUTE6.finditer(_netsh("show", "route").stdout)]
        if left:
            log(f"IPv6 may still leak: default route remains on interface(s) {', '.join(left)}")
        else:
            log("IPv6 can no longer bypass the VPN (default route paused until disconnect)")
    except (OSError, subprocess.SubprocessError) as e:
        log(f"Couldn't block IPv6 outside the VPN: {e}")


def restore_physical_ipv6(log: Callable[[str], None]) -> None:
    """Undo disable_physical_ipv6(), including after a crash (needs admin)."""
    if not IPV6_STATE_FILE.exists():
        return
    try:
        for line in IPV6_STATE_FILE.read_text(encoding="utf-8").splitlines():
            if line.count("|") != 2:
                continue
            metric, idx, gateway = line.split("|")
            _netsh("set", "interface", f"interface={idx}", "ignoredefaultroutes=disabled",
                   "store=active")
            cmd = ["add", "route", "::/0", f"interface={idx}", f"metric={metric}"]
            if ":" in gateway:
                cmd.append(f"nexthop={gateway}")
            _netsh(*cmd, "store=active")  # the router re-announces it soon anyway
        IPV6_STATE_FILE.unlink()
        log("Normal IPv6 restored")
    except (OSError, subprocess.SubprocessError) as e:
        log(f"Couldn't restore IPv6: {e}")


# Lines that end a probe, mapped to its verdict.
_PROBE_RESULTS = [
    ("PUSH_REPLY", "ok"),
    ("AUTH_FAILED", "refused"),
    ("TLS Error", "tls_error"),
    ("TLS handshake failed", "tls_error"),
    ("Connection refused", "unreachable"),
    ("Connection reset", "unreachable"),
    ("Exiting due to fatal error", "error"),
]


_probe_procs: set[subprocess.Popen] = set()


def kill_probes() -> None:
    for p in list(_probe_procs):
        p.kill()


def probe(openvpn_exe: str, config_text: str, timeout: float = 15.0) -> tuple[str, int]:
    """Run the VPN handshake against a server without creating a tunnel
    ('dev null', no routes) and report whether it would let us in.
    Returns (verdict, milliseconds-to-verdict). Works without admin."""
    workdir = tempfile.mkdtemp(prefix="freevpn_probe_")
    cfg = Path(workdir, "probe.ovpn")
    cfg.write_text(config_text + "\ndev null\nroute-nopull\nconnect-retry-max 1\n"
                   "hand-window 12\n", encoding="utf-8")
    start = time.monotonic()
    proc = subprocess.Popen(
        [openvpn_exe, "--config", str(cfg)], cwd=workdir, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, errors="replace",
        creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0)
    _probe_procs.add(proc)
    verdict = "timeout"
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    try:
        for line in proc.stdout:
            hit = next((v for marker, v in _PROBE_RESULTS if marker in line), None)
            if hit:
                verdict = hit
                break
    finally:
        timer.cancel()
        proc.kill()
        proc.wait()
        _probe_procs.discard(proc)
        shutil.rmtree(workdir, ignore_errors=True)
    return verdict, int((time.monotonic() - start) * 1000)


# OpenVPN's own "session lost, restarting" lines. Match these exact forms:
# the server's PUSH_REPLY also contains the words "ping-restart".
_RESTART_SIGNALS = ("SIGUSR1[soft,connection-reset]", "SIGUSR1[soft,ping-restart]")


class VPNConnection:
    """One OpenVPN session. Callbacks are invoked from a worker thread."""

    def __init__(self, on_log: Callable[[str], None], on_state: Callable[[str], None]):
        self.on_log = on_log
        self.on_state = on_state
        self.proc: subprocess.Popen | None = None
        self.mgmt_port = 0
        self.workdir = Path(tempfile.mkdtemp(prefix="freevpn_"))
        self._stopping = False
        self._timed_out = False
        self._connected = threading.Event()
        self._authed = threading.Event()
        self.log_path = Path(__file__).resolve().parent / "logs" / "connection.log"

    def _emit(self, line: str) -> None:
        self.on_log(line)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def reset_log(self) -> None:
        self.log_path.parent.mkdir(exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self, openvpn_exe: str, config_text: str, adapter: str | None = None,
              connect_timeout: float = 30.0, setup_timeout: float = 90.0) -> None:
        """Final states reported: connected, then disconnected; or, if the
        tunnel never came up, refused / timeout / failed."""
        if self.running:
            raise RuntimeError("Already connected")
        if adapter:
            config_text += f"dev-node {adapter}\n"
        # CBC-only servers can't use DCO; say so up front so OpenVPN goes
        # straight to the TAP adapter instead of another app's DCO adapter.
        config_text += "disable-dco\n"
        cfg = self.workdir / "server.ovpn"
        cfg.write_text(config_text, encoding="utf-8")
        self.mgmt_port = _free_port()
        self._stopping = False
        self._timed_out = False
        self._connected = threading.Event()
        self._authed = threading.Event()
        self.log_path.parent.mkdir(exist_ok=True)
        # Append, so a failover run keeps every server's attempt in one file.
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"\n=== {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        cmd = [openvpn_exe, "--config", str(cfg),
               "--management", "127.0.0.1", str(self.mgmt_port)]
        self.on_state("connecting")
        self.proc = subprocess.Popen(
            cmd, cwd=self.workdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        self._started = time.monotonic()
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._watchdog, args=(connect_timeout, setup_timeout),
                         daemon=True).start()

    def _watchdog(self, timeout: float, setup_timeout: float) -> None:
        # Once the server has accepted us (PUSH_REPLY) the remaining work is
        # local adapter/route setup, which can be slow on Windows; give it
        # more time instead of abandoning a server that works.
        deadline = time.monotonic() + timeout
        while not self._connected.wait(0.5):
            if not self.running or self._stopping:
                return
            if self._authed.is_set():
                deadline = max(deadline, self._authed_at + setup_timeout)
            if time.monotonic() > deadline:
                self._timed_out = True
                stage = "setting up the network adapter" if self._authed.is_set() else "reaching the server"
                self._emit(f"Gave up after {time.monotonic() - self._started:.0f}s while {stage}")
                self.stop(report=False)
                return

    def _pump(self) -> None:
        assert self.proc and self.proc.stdout
        refused = dropped = False
        for line in self.proc.stdout:
            line = line.rstrip()
            self._emit(line)
            if "PUSH_REPLY" in line and not self._authed.is_set():
                self._authed_at = time.monotonic()
                self._authed.set()
            if "Initialization Sequence Completed" in line and not self._connected.is_set():
                self._connected.set()
                self.on_state("connected")
            elif (any(sig in line for sig in _RESTART_SIGNALS) and self._authed.is_set()
                  and not self._connected.is_set() and not dropped):
                # The server accepted us but dropped the session while Windows
                # was still setting up the adapter (on PCs with many network
                # adapters that step can stall past the server's ~10s
                # keepalive). Reconnecting to the same server tends to be
                # refused while the old session lingers, so end this attempt
                # now and let the caller try a fresh one.
                dropped = True
                threading.Thread(target=self.stop, kwargs={"report": False},
                                 daemon=True).start()
            elif "AUTH_FAILED" in line:
                refused = True
                if not self._authed.is_set() and not self._stopping:
                    # Refused on first contact: this server isn't taking users.
                    threading.Thread(target=self.stop, kwargs={"report": False},
                                     daemon=True).start()
        self.proc.wait()
        if self._connected.is_set():
            self.on_state("disconnected")
        elif dropped:
            self.on_state("dropped")
        elif refused:
            self.on_state("refused")
        elif self._timed_out:
            self.on_state("timeout")
        elif self._stopping:
            self.on_state("disconnected")
        else:
            self.on_state("failed")

    def stop(self, timeout: float = 8.0, report: bool = True) -> None:
        if not self.running:
            return
        self._stopping = True
        if report:
            self.on_state("disconnecting")
        # A clean SIGTERM via the management interface lets OpenVPN remove its
        # routes and DNS settings; a hard kill can leave them behind.
        try:
            with socket.create_connection(("127.0.0.1", self.mgmt_port), timeout=3) as s:
                s.sendall(b"signal SIGTERM\n")
                time.sleep(0.3)
        except OSError:
            pass
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()

    def cleanup(self) -> None:
        self.stop()
        shutil.rmtree(self.workdir, ignore_errors=True)
