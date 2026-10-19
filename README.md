# FreeVPN

A Surfshark-style desktop VPN client for Windows that connects to the free
public servers of [VPN Gate](https://www.vpngate.net) (University of Tsukuba).

## Setup (one time)
1. Install **OpenVPN Community** (free): https://openvpn.net/community-downloads/
   (Windows 64-bit MSI, default options).
2. Python 3.10+ (no extra packages needed).

## Run
Double-click `FreeVPN.bat`, or `python app.py`. Making a VPN tunnel needs
administrator rights; the app offers to restart itself elevated.

- Left: pick a country (or "All locations"), search to filter.
- Table: every free server with IP, ping, speed, protocol, users and uptime.
  Click column headers to sort. Double-click a row to connect.
- On startup every server is **tested** (a real VPN handshake, no tunnel) and
  marked Working / Refuses users / No response. Roughly 40% of volunteer
  servers refuse new users or are offline at any moment; failed ones are hidden
  by default. Re-run with **Test all servers**.
- **Quick connect** picks the fastest working server in the current location.
- If a server fails while connecting, the app automatically tries the next
  working server (up to 5).
- **Legacy server compatibility** lets OpenVPN accept the old 1024-bit/SHA1
  certificates many volunteer servers still use. Turn it off for stricter TLS
  (fewer servers will work).

## Safety notes
- Servers are run by volunteers. The operator can see your unencrypted traffic
  and VPN Gate keeps connection logs. Use HTTPS, don't treat it as anonymous.
- Configs are sanitized before use: script hooks, plugins and file-writing
  directives are stripped, and `script-security 1` is forced.
- VPN Gate is IPv4-only, so IPv6 is blocked while connected; otherwise your
  real IPv6 address would bypass the VPN. While connected, the Wi-Fi/Ethernet
  IPv6 default route is paused (netsh, "active" store only, so a reboot also
  undoes it) and restored on disconnect, or on the next start after a crash.
  The header shows both addresses.
- Every attempt, including FreeVPN's own steps, is logged to
  `logs/connection.log`.
- DNS is set to 1.1.1.1 / 8.8.8.8 with `block-outside-dns` to prevent DNS leaks.
