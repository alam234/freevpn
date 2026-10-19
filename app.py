"""FreeVPN - a desktop VPN client for free public VPN Gate servers."""

from __future__ import annotations

import queue
import sys
import threading
import time
import traceback
import tkinter as tk
import urllib.request
import webbrowser
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import messagebox, ttk

sys.path.insert(0, str(Path(__file__).resolve().parent))

import servers as srv  # noqa: E402
from connection import (VPNConnection, clear_stale_routes, ensure_adapter,  # noqa: E402
                        find_openvpn, is_admin, kill_probes, probe, relaunch_as_admin,
                        set_ipv6_block, disable_physical_ipv6, restore_physical_ipv6)

CACHE = Path(__file__).resolve().parent / "server_cache.csv"
OPENVPN_DOWNLOAD = "https://openvpn.net/community-downloads/"
IPV4_SERVICES = ["https://ipv4.icanhazip.com", "https://checkip.amazonaws.com",
                 "https://api.ipify.org"]
IPV6_SERVICES = ["https://ipv6.icanhazip.com", "https://api6.ipify.org"]
PROBE_WORKERS = 6
MAX_FAILOVER = 8

BG = "#0f1724"
PANEL = "#16213a"
CARD = "#1c2a47"
FG = "#e6edf7"
MUTED = "#8a9bb8"
ACCENT = "#1ebfbf"
GOOD = "#3fb950"
DANGER = "#e5534b"
WARN = "#e3b341"

STATE_STYLE = {
    "disconnected": ("Not connected", MUTED),
    "connecting": ("Connecting...", WARN),
    "connected": ("Connected", ACCENT),
    "disconnecting": ("Disconnecting...", WARN),
    "failed": ("Connection failed", DANGER),
    "refused": ("Server refused the connection", DANGER),
    "timeout": ("Server didn't respond", DANGER),
    "dropped": ("Connection dropped during setup", DANGER),
}

# Probe verdict -> (label in the Status column, row tag)
VERDICTS = {
    "ok": ("Working", "ok"),
    "refused": ("Refuses users", "bad"),
    "timeout": ("No response", "bad"),
    "tls_error": ("No response", "bad"),
    "unreachable": ("Unreachable", "bad"),
    "error": ("Error", "bad"),
    "failed": ("Failed", "bad"),
    "testing": ("Testing...", "testing"),
}


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("FreeVPN")
        self.geometry("1240x740")
        self.minsize(1000, 620)
        self.configure(bg=BG)

        self.servers: list[srv.Server] = []
        self.health: dict[str, tuple[str, int]] = {}  # ip -> (verdict, ms)
        self.selected_country: str | None = None
        self.active_server: srv.Server | None = None
        self.vpn_state = "disconnected"
        self.failover: list[srv.Server] = []
        self.attempts = 0
        self.adapter: str | None = None
        self.adapter_checked = False
        self.probe_gen = 0
        self.probing = False
        self.events: queue.Queue = queue.Queue()
        self.vpn = VPNConnection(
            on_log=lambda line: self.events.put(("log", line)),
            on_state=lambda st: self.events.put(("state", st)),
        )
        self.legacy = tk.BooleanVar(value=True)
        self.block_ipv6 = tk.BooleanVar(value=True)
        self.auto_failover = tk.BooleanVar(value=True)
        self.hide_failed = tk.BooleanVar(value=True)
        self.hide_failed.trace_add("write", lambda *_: self._render_all())
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self._render_countries())

        self._style()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._drain_events)

        if CACHE.exists():
            self._load_servers(srv.parse(CACHE.read_text(encoding="utf-8")), cached=True)
        self.refresh_servers()
        if is_admin():
            # Undo an IPv6 block left behind if the app was killed mid-session.
            def restore():
                restore_physical_ipv6(lambda m: self.events.put(("log", m)))
                self.events.put(("recheck_ip", None))
            threading.Thread(target=restore, daemon=True).start()
        else:
            self.refresh_public_ip()

    # ---------- UI ----------
    def _style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, fieldbackground=PANEL, font=("Segoe UI", 10))
        s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG,
                    rowheight=28, borderwidth=0)
        s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", BG)])
        s.configure("Treeview.Heading", background=CARD, foreground=MUTED,
                    font=("Segoe UI", 9, "bold"), relief="flat")
        s.map("Treeview.Heading", background=[("active", CARD)])
        for name, bg in (("TCheckbutton", CARD), ("Panel.TCheckbutton", PANEL)):
            s.configure(name, background=bg, foreground=MUTED)
            s.map(name, background=[("active", bg)])
        s.configure("Vertical.TScrollbar", background=CARD, troughcolor=PANEL, borderwidth=0)

    def _btn(self, parent, text, cmd, bg=ACCENT, fg=BG, **kw) -> tk.Button:
        return tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg, activebackground=bg,
                         activeforeground=fg, relief="flat", bd=0, cursor="hand2",
                         font=kw.pop("font", ("Segoe UI", 10, "bold")), padx=14, pady=6, **kw)

    def _build(self) -> None:
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=18, pady=(14, 8))
        tk.Label(header, text="Free", bg=BG, fg=FG, font=("Segoe UI", 18, "bold")).pack(side="left")
        tk.Label(header, text="VPN", bg=BG, fg=ACCENT, font=("Segoe UI", 18, "bold")).pack(side="left")
        self.ip_label = tk.Label(header, text="Checking your IP...", bg=BG, fg=MUTED, font=("Segoe UI", 10))
        self.ip_label.pack(side="right")
        self.list_label = tk.Label(header, text="", bg=BG, fg=MUTED, font=("Segoe UI", 9))
        self.list_label.pack(side="right", padx=18)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 14))

        # Left: countries
        left = tk.Frame(body, bg=PANEL, width=280)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Label(left, text="Locations", bg=PANEL, fg=FG, font=("Segoe UI", 12, "bold")
                 ).pack(anchor="w", padx=14, pady=(14, 6))
        entry = tk.Entry(left, textvariable=self.search, bg=CARD, fg=FG, insertbackground=FG,
                         relief="flat", font=("Segoe UI", 10))
        entry.pack(fill="x", padx=14, pady=(0, 10), ipady=6)
        bottom = tk.Frame(left, bg=PANEL)
        bottom.pack(side="bottom", fill="x", padx=14, pady=(0, 14))
        ttk.Checkbutton(bottom, text="Hide servers that failed the test",
                        variable=self.hide_failed, style="Panel.TCheckbutton"
                        ).pack(anchor="w", pady=(0, 8))
        self.test_btn = self._btn(bottom, "Test all servers", self.start_probe, bg=CARD, fg=FG)
        self.test_btn.pack(fill="x", pady=(0, 6))
        self._btn(bottom, "Refresh server list", self.refresh_servers, bg=CARD, fg=FG
                  ).pack(fill="x")
        self.countries = ttk.Treeview(left, columns=("n",), show="tree", selectmode="browse")
        self.countries.column("#0", width=190)
        self.countries.column("n", width=56, anchor="e")
        self.countries.pack(fill="both", expand=True, padx=(14, 4), pady=(0, 8))
        self.countries.bind("<<TreeviewSelect>>", self._on_country)

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(14, 0))

        # Connection card
        card = tk.Frame(right, bg=CARD)
        card.pack(fill="x")
        info = tk.Frame(card, bg=CARD)
        info.pack(side="left", fill="both", expand=True, padx=20, pady=18)
        self.status_label = tk.Label(info, text="Not connected", bg=CARD, fg=MUTED,
                                     font=("Segoe UI", 20, "bold"))
        self.status_label.pack(anchor="w")
        self.server_label = tk.Label(info, text="Pick a location, then a server", bg=CARD,
                                     fg=MUTED, font=("Segoe UI", 10), justify="left")
        self.server_label.pack(anchor="w", pady=(4, 8))
        ttk.Checkbutton(info, text="If a server fails, automatically try the next working one",
                        variable=self.auto_failover).pack(anchor="w")
        ttk.Checkbutton(info, text="Legacy server compatibility (accept old 1024-bit/SHA1 certificates)",
                        variable=self.legacy).pack(anchor="w")
        ttk.Checkbutton(info, text="Block IPv6 so it can't leak around the VPN (VPN Gate is IPv4-only)",
                        variable=self.block_ipv6).pack(anchor="w")

        actions = tk.Frame(card, bg=CARD)
        actions.pack(side="right", padx=20, pady=18)
        self.connect_btn = self._btn(actions, "CONNECT", self.toggle_connection,
                                     font=("Segoe UI", 13, "bold"), width=14)
        self.connect_btn.configure(pady=12)
        self.connect_btn.pack()
        self._btn(actions, "Quick connect (fastest working)", self.quick_connect, bg=PANEL, fg=FG
                  ).pack(fill="x", pady=(8, 0))

        # Server table
        tk.Label(right, text="Available free servers", bg=BG, fg=FG,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", pady=(16, 6))
        table = tk.Frame(right, bg=BG)
        table.pack(fill="both", expand=True)
        cols = [("status", "Status", 120), ("ip", "IP address", 125), ("country", "Country", 115),
                ("ping", "Ping", 55), ("speed", "Speed", 90), ("proto", "Protocol", 85),
                ("sessions", "Users", 55), ("uptime", "Uptime", 65), ("score", "Score", 85),
                ("host", "Host", 120)]
        self.table = ttk.Treeview(table, columns=[c[0] for c in cols], show="headings",
                                  selectmode="browse")
        for key, title, width in cols:
            self.table.heading(key, text=title, command=lambda k=key: self._sort(k))
            self.table.column(key, width=width,
                              anchor="w" if key in ("status", "ip", "country", "host") else "e")
        self.table.tag_configure("ok", foreground=GOOD)
        self.table.tag_configure("bad", foreground=DANGER)
        self.table.tag_configure("testing", foreground=WARN)
        sb = ttk.Scrollbar(table, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=sb.set)
        self.table.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", self._on_server_select)
        self.table.bind("<Double-1>", lambda e: self.connect_selected())
        self._sort_key, self._sort_rev = "status", False
        self._row_map: dict[str, srv.Server] = {}

        # Log
        logf = tk.Frame(right, bg=BG)
        logf.pack(fill="x", pady=(10, 0))
        tk.Label(logf, text="Connection log", bg=BG, fg=MUTED, font=("Segoe UI", 9, "bold")
                 ).pack(anchor="w")
        self.log = tk.Text(logf, height=7, bg=PANEL, fg=MUTED, relief="flat",
                           font=("Consolas", 9), state="disabled", wrap="none")
        self.log.pack(fill="x")

    # ---------- data ----------
    def refresh_servers(self) -> None:
        self.list_label.config(text="Downloading server list...")

        def work():
            try:
                raw = srv.fetch_raw()
                parsed = srv.parse(raw)
                if parsed:
                    CACHE.write_text(raw, encoding="utf-8")
                self.events.put(("servers", parsed))
            except Exception as e:  # network errors, HTTP errors, bad data
                self.events.put(("servers_error", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def refresh_public_ip(self) -> None:
        def lookup(urls, looks_ok):
            for url in urls:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
                    with urllib.request.urlopen(req, timeout=5) as r:
                        candidate = r.read(64).decode().strip()
                    if looks_ok(candidate):
                        return candidate
                except Exception:
                    continue
            return None

        def work():
            v4 = lookup(IPV4_SERVICES, lambda x: x.count(".") == 3)
            v6 = lookup(IPV6_SERVICES, lambda x: ":" in x)
            self.events.put(("ip", (v4, v6)))

        threading.Thread(target=work, daemon=True).start()

    def _load_servers(self, servers: list[srv.Server], cached: bool = False) -> None:
        self.servers = servers
        self._cached = cached
        self._update_summary()
        self._render_countries()
        if not cached:
            self.start_probe()

    def _update_summary(self) -> None:
        n_c = len({s.country for s in self.servers})
        text = f"{len(self.servers)} free servers in {n_c} countries"
        if self.probing:
            done = sum(1 for s in self.servers if self.health.get(s.ip, ("testing",))[0] != "testing")
            text += f"  -  testing {done}/{len(self.servers)}..."
        elif self.health:
            ok = sum(1 for s in self.servers if self.health.get(s.ip, ("",))[0] == "ok")
            text += f"  -  {ok} working right now"
        elif getattr(self, "_cached", False):
            text += " (cached)"
        self.list_label.config(text=text)

    # ---------- server testing ----------
    def start_probe(self) -> None:
        exe = find_openvpn()
        if not exe or not self.servers or self.probing:
            return
        self.probe_gen += 1
        gen = self.probe_gen
        self.probing = True
        self.test_btn.config(state="disabled", text="Testing servers...")
        targets = list(self.servers)
        for s in targets:
            self.health[s.ip] = ("testing", 0)
        self._render_all()
        legacy = self.legacy.get()

        def one(s: srv.Server):
            if gen != self.probe_gen:  # superseded, or the app is closing
                return
            verdict, ms = probe(exe, srv.sanitize_config(s.config_text, legacy))
            self.events.put(("probe", (gen, s.ip, verdict, ms)))

        def work():
            with ThreadPoolExecutor(PROBE_WORKERS) as ex:
                list(ex.map(one, targets))
            self.events.put(("probe_done", gen))

        threading.Thread(target=work, daemon=True).start()

    def _on_probe(self, gen: int, ip: str, verdict: str, ms: int) -> None:
        if gen != self.probe_gen:
            return
        self.health[ip] = (verdict, ms)
        if self.table.exists(ip):
            self.table.item(ip, values=self._row_values(self._row_map[ip]),
                            tags=(self._row_tag(ip),))
        self._update_summary()

    def _on_probe_done(self, gen: int) -> None:
        if gen != self.probe_gen:
            return
        self.probing = False
        self.test_btn.config(state="normal", text="Test all servers")
        self._update_summary()
        self._render_all()

    def _verdict(self, ip: str) -> str | None:
        h = self.health.get(ip)
        return h[0] if h else None

    def _status_text(self, ip: str) -> str:
        h = self.health.get(ip)
        if not h:
            return "Not tested"
        label = VERDICTS.get(h[0], (h[0], ""))[0]
        if h[0] == "ok":
            return f"✓ {label} {h[1] / 1000:.1f}s"
        if h[0] == "testing":
            return label
        return f"✗ {label}"

    def _row_tag(self, ip: str) -> str:
        v = self._verdict(ip)
        return VERDICTS[v][1] if v in VERDICTS else ""

    # ---------- rendering ----------
    def _render_all(self) -> None:
        self._render_countries()

    def _shown(self, s: srv.Server) -> bool:
        v = self._verdict(s.ip)
        return not (self.hide_failed.get() and v not in (None, "ok", "testing"))

    def _render_countries(self) -> None:
        total = Counter(s.country for s in self.servers)
        working = Counter(s.country for s in self.servers if self._verdict(s.ip) == "ok")
        tested = bool(self.health) and not self.probing
        q = self.search.get().strip().lower()
        self.countries.delete(*self.countries.get_children())

        def count(n_ok, n):
            return f"{n_ok}/{n}" if tested else str(n)

        self.countries.insert("", "end", iid="__all__", text="  All locations",
                              values=(count(sum(working.values()), len(self.servers)),))
        for country, n in sorted(total.items()):
            if q and q not in country.lower():
                continue
            code = next(s.country_code for s in self.servers if s.country == country)
            self.countries.insert("", "end", iid=country, text=f"  {code}   {country}",
                                  values=(count(working[country], n),))
        target = self.selected_country or "__all__"
        if self.countries.exists(target):
            self.countries.selection_set(target)
        self._render_servers()

    def _visible_servers(self) -> list[srv.Server]:
        if not self.selected_country:
            return list(self.servers)
        return [s for s in self.servers if s.country == self.selected_country]

    def _row_values(self, s: srv.Server) -> tuple:
        return (self._status_text(s.ip), s.ip, s.country, f"{s.ping} ms" if s.ping else "-",
                f"{s.speed_mbps:.1f} Mbps", f"{s.protocol}/{s.port}", s.sessions,
                f"{s.uptime_days:.0f} d", f"{s.score:,}", s.hostname)

    def _status_rank(self, s: srv.Server):
        v = self._verdict(s.ip)
        order = {"ok": 0, "testing": 1, None: 2}.get(v, 3)
        ms = self.health[s.ip][1] if v == "ok" else 0
        return (order, ms, -s.score)

    def _render_servers(self) -> None:
        keyfn = {
            "status": self._status_rank,
            "ip": lambda s: tuple(int(p) for p in s.ip.split(".") if p.isdigit()),
            "country": lambda s: s.country, "ping": lambda s: s.ping or 9999,
            "speed": lambda s: s.speed_bps, "proto": lambda s: s.protocol,
            "sessions": lambda s: s.sessions, "uptime": lambda s: s.uptime_ms,
            "score": lambda s: s.score, "host": lambda s: s.hostname,
        }[self._sort_key]
        selected = self.table.selection()
        rows = sorted((s for s in self._visible_servers() if self._shown(s)),
                      key=keyfn, reverse=self._sort_rev)
        self.table.delete(*self.table.get_children())
        self._row_map = {}
        for s in rows:
            if s.ip in self._row_map:
                continue
            self._row_map[s.ip] = s
            self.table.insert("", "end", iid=s.ip, values=self._row_values(s),
                              tags=(self._row_tag(s.ip),))
        if selected and self.table.exists(selected[0]):
            self.table.selection_set(selected[0])
            self.table.see(selected[0])

    def _sort(self, key: str) -> None:
        self._sort_rev = not self._sort_rev if key == self._sort_key else key in (
            "speed", "score", "uptime")
        self._sort_key = key
        self._render_servers()

    def _on_country(self, _e=None) -> None:
        sel = self.countries.selection()
        if not sel:
            return
        self.selected_country = None if sel[0] == "__all__" else sel[0]
        self._render_servers()

    def _selected_server(self) -> srv.Server | None:
        sel = self.table.selection()
        return self._row_map.get(sel[0]) if sel else None

    def _on_server_select(self, _e=None) -> None:
        s = self._selected_server()
        if s and not self.vpn.running:
            self.server_label.config(text=self._describe(s))

    @staticmethod
    def _describe(s: srv.Server) -> str:
        return (f"{s.country}  -  {s.ip}  ({s.protocol} {s.port})\n"
                f"{s.speed_mbps:.1f} Mbps, {s.ping or '?'} ms ping, {s.sessions} users  "
                f"|  operator: {s.operator[:40] or 'unknown'}")

    # ---------- connection ----------
    def _working(self, pool: list[srv.Server], exclude: srv.Server | None = None) -> list[srv.Server]:
        ok = [s for s in pool if self._verdict(s.ip) == "ok" and s is not exclude]
        return sorted(ok, key=lambda s: self.health[s.ip][1])

    def toggle_connection(self) -> None:
        if self.vpn.running:
            self.failover = []
            threading.Thread(target=self.vpn.stop, daemon=True).start()
        else:
            self.connect_selected()

    def quick_connect(self) -> None:
        pool = self._visible_servers()
        if not pool:
            messagebox.showinfo("FreeVPN", "No servers loaded yet.")
            return
        candidates = self._working(pool)
        if not candidates:
            # Nothing verified yet: fall back to untested servers by score.
            candidates = sorted((s for s in pool if self._verdict(s.ip) in (None, "testing")),
                                key=lambda s: s.score, reverse=True)
        if not candidates:
            messagebox.showinfo("FreeVPN", "No working servers in this location right now.\n"
                                "Pick another location or press 'Test all servers'.")
            return
        self._connect(candidates[0], candidates[1:])

    def connect_selected(self) -> None:
        s = self._selected_server()
        if not s:
            messagebox.showinfo("FreeVPN", "Select a server from the list, or use Quick connect.")
            return
        same_country = [x for x in self.servers if x.country == s.country]
        self._connect(s, self._working(same_country, exclude=s) or self._working(self.servers, s))

    def _connect(self, s: srv.Server, backups: list[srv.Server]) -> None:
        if self.vpn.running:
            messagebox.showinfo("FreeVPN", "Disconnect first.")
            return
        exe = find_openvpn()
        if not exe:
            if messagebox.askyesno(
                    "OpenVPN required",
                    "FreeVPN uses the OpenVPN engine, which isn't installed.\n\n"
                    "Open the official OpenVPN download page now?"):
                webbrowser.open(OPENVPN_DOWNLOAD)
            return
        if not is_admin():
            if messagebox.askyesno(
                    "Administrator rights needed",
                    "Creating a VPN tunnel needs administrator rights.\n\n"
                    "Restart FreeVPN as administrator?"):
                if relaunch_as_admin():
                    self._on_close(force=True)
            return
        self.failover = backups[:MAX_FAILOVER] if self.auto_failover.get() else []
        self.attempts = 0
        self._log_clear()
        self.vpn.reset_log()
        self._start(exe, s)

    def _start(self, exe: str, s: srv.Server) -> None:
        self.attempts += 1
        self.active_server = s
        self.server_label.config(text=self._describe(s))
        self._log(f"[{self.attempts}] Connecting to {s.ip} ({s.country}, {s.protocol} {s.port})")
        self._set_state("connecting")
        config = srv.sanitize_config(s.config_text, self.legacy.get())

        def work():
            if not self.adapter_checked:
                self.adapter = ensure_adapter(exe, lambda m: self.events.put(("log", m)))
                self.adapter_checked = True
            if self.adapter and self.attempts == 1:
                clear_stale_routes(self.adapter, lambda m: self.events.put(("log", m)))
            try:
                self.vpn.start(exe, config, adapter=self.adapter)
            except Exception as e:
                self.events.put(("log", f"Failed to start OpenVPN: {e}"))
                self.events.put(("state", "failed"))

        threading.Thread(target=work, daemon=True).start()

    def _set_state(self, st: str) -> None:
        self.vpn_state = st
        server = self.active_server
        if st in ("refused", "timeout", "failed", "dropped") and server:
            if st != "dropped":  # a drop is the PC being slow, not the server
                self.health[server.ip] = (st, 0)
            if self.table.exists(server.ip):
                self.table.item(server.ip, values=self._row_values(server),
                                tags=(self._row_tag(server.ip),))
            if self.failover:
                nxt = self.failover.pop(0)
                reason = STATE_STYLE[st][0].lower()
                self._log(f"{server.ip}: {reason}. Trying next working server...")
                exe = find_openvpn()
                if exe:
                    self.after(400, lambda: self._start(exe, nxt))
                    return

        text, color = STATE_STYLE.get(st, (st, MUTED))
        if st == "connected" and server:
            text = f"Connected - {server.country}"
            self.health[server.ip] = ("ok", self.health.get(server.ip, ("ok", 0))[1])
        if st in ("refused", "timeout", "failed", "dropped") and self.attempts > 1:
            text = f"Couldn't connect ({self.attempts} servers tried)"
        self.status_label.config(text=text, fg=color)
        if st in ("connected", "connecting"):
            self.connect_btn.config(text="DISCONNECT", bg=DANGER, activebackground=DANGER)
        else:
            self.connect_btn.config(text="CONNECT", bg=ACCENT, activebackground=ACCENT)
        self.connect_btn.config(state="disabled" if st == "disconnecting" else "normal")
        if st == "connected" and self.adapter and self.block_ipv6.get():
            self.ip_label.config(text="Checking your IP...", fg=MUTED)
            self._ipv6_blocked = True
            adapter = self.adapter

            def block():
                log = self._applog
                try:
                    set_ipv6_block(adapter, True, log)
                    disable_physical_ipv6(adapter, log)
                except Exception:
                    log("IPv6 block failed:\n" + traceback.format_exc())
                self.events.put(("recheck_ip", None))

            threading.Thread(target=block, daemon=True).start()
        elif st == "connected":
            self.ip_label.config(text="Checking your IP...", fg=MUTED)
            self.after(1500, self.refresh_public_ip)
        if st not in ("connected", "connecting") and getattr(self, "_ipv6_blocked", False):
            self._ipv6_blocked = False
            adapter = self.adapter

            def unblock():
                log = self._applog
                try:
                    restore_physical_ipv6(log)
                    set_ipv6_block(adapter, False, log)
                except Exception:
                    log("IPv6 restore failed:\n" + traceback.format_exc())
                self.events.put(("recheck_ip", None))

            threading.Thread(target=unblock, daemon=True).start()
        elif st == "disconnected":
            self.ip_label.config(text="Checking your IP...", fg=MUTED)
            self.after(1500, self.refresh_public_ip)
        if st in ("refused", "timeout", "failed", "dropped"):
            self._log("Tip: volunteer servers go offline or stop accepting users often. "
                      "Pick a server marked Working, or press 'Test all servers'.")

    def _show_ip(self, v4: str | None, v6: str | None) -> None:
        text = f"IPv4: {v4 or 'unavailable'}"
        color = MUTED
        if v6:
            text += f"   IPv6: {v6}"
            if self.vpn_state == "connected":
                text += "  (LEAKING - not via VPN)"
                color = DANGER
        elif self.vpn_state == "connected":
            text += "   IPv6: blocked"
            color = GOOD
        self.ip_label.config(text=text, fg=color)

    # ---------- plumbing ----------
    def _applog(self, line: str) -> None:
        """Log an app message (thread-safe) and keep it in connection.log."""
        self.events.put(("log", line))
        try:
            with open(self.vpn.log_path, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [app] {line}\n")
        except OSError:
            pass

    def _log(self, line: str) -> None:
        self.log.config(state="normal")
        self.log.insert("end", line + "\n")
        if int(self.log.index("end-1c").split(".")[0]) > 600:
            self.log.delete("1.0", "100.0")
        self.log.see("end")
        self.log.config(state="disabled")

    def _log_clear(self) -> None:
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

    def _drain_events(self) -> None:
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "log":
                    self._log(data)
                elif kind == "state":
                    self._set_state(data)
                elif kind == "ip":
                    self._show_ip(*data)
                elif kind == "servers":
                    self._load_servers(data)
                elif kind == "servers_error":
                    self.list_label.config(text="Couldn't download server list"
                                           + (" - showing cached list" if self.servers else ""))
                    self._log(f"Server list download failed: {data}")
                    if self.servers and not self.health:
                        self.start_probe()
                elif kind == "recheck_ip":
                    self.after(1000, self.refresh_public_ip)
                elif kind == "probe":
                    self._on_probe(*data)
                elif kind == "probe_done":
                    self._on_probe_done(data)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _on_close(self, force: bool = False) -> None:
        if self.vpn.running and not force:
            if not messagebox.askyesno("FreeVPN", "Disconnect the VPN and quit?"):
                return
        self.probe_gen += 1
        kill_probes()
        self.vpn.cleanup()
        if getattr(self, "_ipv6_blocked", False) and self.adapter:
            set_ipv6_block(self.adapter, False, lambda m: None)
        if is_admin():
            restore_physical_ipv6(lambda m: None)
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
