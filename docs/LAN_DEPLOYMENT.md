# Deploying NIDPS on a campus LAN

NIDPS can run in two modes. Pick one with `NIDPS_MODE` in `backend/.env`.

| | **Host mode** (`host`, default) | **Gateway mode** (`gateway`) |
|---|---|---|
| Protects | The machine NIDPS runs on | Every machine on a small network routed *through* NIDPS |
| Firewall | Linux: `INPUT` → `NIDPS` chain. Windows: Windows Firewall rules `NIDPS-block-<ip>` | `FORWARD` → `NIDPS` (Linux only) |
| Hardware | One Linux **or Windows** machine (laptop or VM) | A Linux machine with **two** network ports (a USB-Ethernet adapter is fine) + a small switch |
| Needs campus IT? | No | No (your demo network is your own); you only plug its WAN side into the campus network |
| Demo story | "Attacker attacks the NIDPS server; NIDPS blocks the attacker" | "Attacker attacks a victim PC; NIDPS, sitting in the path, blocks the attacker before it reaches the victim" |

> **Before you start:** port scans and attack traffic on a campus network can break
> the acceptable-use policy even when they are aimed at your own machines. Use your own
> switch, hotspot or lab VLAN, or get written permission from IT and your supervisor.
> Many campus Wi-Fi networks also isolate clients from each other, so two laptops on
> eduroam may not be able to reach each other at all. A cheap switch or a phone hotspot
> avoids both problems.

---

## Which machine should run NIDPS?

| Option | Works for | Notes |
|---|---|---|
| **Native Linux laptop / mini-PC** | Host + gateway | Best choice. Everything behaves exactly as documented. |
| **Linux VM, bridged networking** (VirtualBox/VMware "Bridged Adapter") | Host + gateway | The VM gets its own LAN IP. For gateway mode give the VM two bridged adapters. |
| **Native Windows 10/11** (Snort for Windows + Windows Firewall) | Host mode | Protects Windows itself. See [Host mode on native Windows](#host-mode-on-native-windows). Gateway mode is not supported on Windows. |
| Windows + WSL2 (default NAT networking, `NIDPS_FIREWALL=wsl`) | Development and the simulator only | WSL2 sits behind a private NAT: other LAN machines cannot reach it, and iptables in WSL protects only the WSL VM, **not Windows**. |
| Windows + WSL2 with `networkingMode=mirrored` (`NIDPS_FIREWALL=wsl`) | Host mode with care | WSL shares the PC's LAN address, but iptables still only protects services running *inside* WSL. Run the "victim" services (sshd, a web server) in WSL. |

To enable WSL mirrored networking, create `%UserProfile%\.wslconfig` with these lines, then run `wsl --shutdown`:

```ini
[wsl2]
networkingMode=mirrored
```

---

## Common steps (both modes)

On the NIDPS machine (Ubuntu 24.04):

```bash
# 1. Prerequisites
sudo apt-get update && sudo apt-get install -y nodejs npm snort docker.io docker-compose-v2

# 2. Install and build
cd backend && npm install && cd ../frontend && npm install && npm run build && cd ..

# 3. First-time setup: creates backend/.env, asks for the admin password
cd backend && npm run setup

# 4. Database (optional but recommended - otherwise data is lost on restart)
#    Set DB_PASSWORD in backend/.env first.
cd .. && docker compose --env-file backend/.env up -d
```

Edit `backend/.env`:

```ini
ENABLE_REAL_FIREWALL=true
SNORT_LOG_PATH=/var/log/snort/snort.alert.fast
NIDPS_ALLOWLIST=<gateway IP>,<DNS server IP>,<admin PC IP>
DEMO_MODE=true          # keep the simulator for the presentation
```

**Let NIDPS run iptables without being root.** `setup_snort.sh` (below) does this for you. It
installs a small root-owned wrapper, `/usr/local/sbin/nidps-iptables`, and writes this sudo rule
to `/etc/sudoers.d/nidps`:

```
student ALL=(root) NOPASSWD: /usr/local/sbin/nidps-iptables
```

The wrapper accepts **only** NIDPS's own rule shapes on the `NIDPS` chain (create, flush,
jump, and DROP for one validated address). Never grant `NOPASSWD` on plain `iptables`:
`iptables --modprobe=<program>` would let that user run any program as root.
To check the wrapper's rules: `bash backend/test/nidps-iptables.cases.sh`.

If you run NIDPS itself as root (for example in a lab VM), no sudo rule is needed.

**Optional HTTPS** (recommended if anyone else is on the network):

```bash
./backend/scripts/gen-cert.sh
# backend/.env:  TLS_CERT=../certs/nidps.crt   TLS_KEY=../certs/nidps.key
```

**Open the dashboard port** if the machine has a firewall:
- Ubuntu: `sudo ufw allow 5000/tcp`
- Windows (only if NIDPS runs natively on Windows):

```powershell
New-NetFirewallRule -DisplayName "NIDPS dashboard" -Direction Inbound -Protocol TCP -LocalPort 5000 -Action Allow -Profile Private
```

---

## Host mode (protect this machine)

```
   Attacker PC  ──────── LAN / switch ──────── NIDPS machine
   192.168.1.20                                 192.168.1.10
   (nmap, ssh, curl)                            Snort + NIDPS + victim services (sshd, web)
```

1. Find the NIDPS machine's LAN address with `ip -br addr`, for example `192.168.1.10/24`.
2. Configure Snort for that network:
   `sudo ./backend/scripts/setup_snort.sh eth0 192.168.1.0/24 $USER`
3. `NIDPS_MODE=host` in `backend/.env`.
4. Start everything (two terminals):
   ```bash
   sudo ./backend/scripts/start_snort.sh eth0
   cd backend && npm start
   ```
   The server prints the LAN address of the dashboard, for example `http://192.168.1.10:5000`.
5. From the attacker PC:
   ```bash
   nmap -sS -p 1-1000 192.168.1.10                         # P1 "Possible Nmap SYN Scan" -> instant block
   for i in 1 2 3 4 5 6; do ssh -o ConnectTimeout=2 x@192.168.1.10; done   # P2 x5 -> escalation block
   ```
6. Verify on the NIDPS machine: `sudo iptables -L NIDPS -n -v` shows a DROP rule for the attacker, and the packet counter rises while the attacker keeps trying.

---

## Host mode on native Windows

Everything runs on Windows itself: Snort for Windows captures traffic, and NIDPS blocks
attackers with **Windows Firewall** rules named `NIDPS-block-<ip>` (one inbound, one
outbound). NIDPS never touches any other firewall rule.

```
   Attacker PC  ──────── LAN / switch / hotspot ──────── Windows PC
   192.168.1.20                                          192.168.1.10
   (nmap, ssh, curl)                                     Snort + NIDPS + victim services
```

**Install once** (download these yourself from their official websites):
1. **Npcap**, with *"Install Npcap in WinPcap API-compatible Mode"* ticked (Snort 2.9 needs it).
2. **Snort 2.9 for Windows** (the installer), to the default folder `C:\Snort`.
3. **Node.js LTS** (18 or later).

**Set up** (PowerShell opened with *Run as administrator*, in the project folder):
1. Find your address and network with `ipconfig` (for example `192.168.1.10`, mask `255.255.255.0`, so the network is `192.168.1.0/24`).
2. `cd backend\scripts\windows`, then `.\setup-snort.ps1 -HomeNet 192.168.1.0/24`. It writes
   `C:\Snort\etc\nidps.conf` and the rules, then lists your adapters. Note the **Index** of the
   adapter that faces the network (Wi-Fi or Ethernet) and test it:
   `.\setup-snort.ps1 -HomeNet 192.168.1.0/24 -Interface 3`.
   If PowerShell refuses to run scripts: `Set-ExecutionPolicy -Scope Process Bypass` (this window only).
3. In `backend\.env`:
   ```ini
   NIDPS_MODE=host
   NIDPS_FIREWALL=auto
   ENABLE_REAL_FIREWALL=true
   SNORT_LOG_PATH=C:\Snort\log\snort.alert.fast
   SNORT_INTERFACE=3
   NIDPS_ALLOWLIST=192.168.1.1
   ```
4. Give the attacker something to hit. Windows drops pings and closed-port traffic by default,
   so open what you want to demonstrate. These allow rules are yours; NIDPS's block rules still
   win, because in Windows Firewall a block rule overrides an allow rule.
   ```powershell
   Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In        # answer pings
   python -m http.server 8080                           # a victim web server (any app on 8080 works)
   New-NetFirewallRule -DisplayName "Demo web 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow
   ```
   Snort still sees SYN scans and SSH attempts to closed ports, so the Nmap and SSH
   signatures work without opening anything.
5. Start everything (two elevated PowerShell windows):
   ```powershell
   .\backend\scripts\windows\start-snort.ps1 -Interface 3
   cd backend; npm start
   ```
   Without Administrator rights NIDPS stops at start-up with a clear message, rather than failing later.
6. Pre-flight: `.\backend\scripts\windows\check-windows.ps1` must say "All 9 checks passed".
7. Attack from the other PC exactly as in host mode above (`nmap -sS`, repeated `ssh`,
   `curl "http://192.168.1.10:8080/?q=1%20union%20select%202"`).
8. Verify: `Get-NetFirewallRule -DisplayName 'NIDPS-block-*' | Format-Table DisplayName,Direction,Action`
   lists the attacker, and the attacker's `ping` now times out.

Optional: `.\backend\scripts\windows\install-task.ps1 -SnortInterface 3` starts NIDPS and Snort
automatically (elevated) when you sign in; `-Remove` undoes it.

Windows Firewall rules survive a reboot, unlike iptables. NIDPS still removes every
`NIDPS-block-*` rule at start-up and re-applies only the blocks that are active in its database.

---

## Gateway mode (protect a network behind NIDPS)

The attacker must be **outside** the protected network, so that its traffic has to pass
through the gateway. Two PCs on the same inside switch talk to each other directly and
the gateway never sees that traffic.

```
   Attacker PC (campus side)  e.g. 192.168.1.20
        │      route: 192.168.50.0/24 via <gateway WAN IP>
 Campus LAN / your own switch or hotspot
        │
   wan_if (e.g. wlan0 or eth0)  e.g. 192.168.1.10
 ┌──────┴──────────────────────────┐
 │  NIDPS gateway (Linux)          │   Snort listens on lan_if
 │  NAT + FORWARD → NIDPS chain    │   NIDPS blocks in FORWARD
 └──────┬──────────────────────────┘
   lan_if (e.g. eth1, USB-Ethernet) 192.168.50.1/24
        │
   Victim PC 192.168.50.10  (gateway 192.168.50.1; runs sshd / a web server)
```

| Device | Address | Gateway | DNS |
|---|---|---|---|
| NIDPS `wan_if` | from the outside network (e.g. 192.168.1.10) | outside router | — |
| NIDPS `lan_if` | 192.168.50.1/24 | — | — |
| Victim PC | 192.168.50.10/24 | 192.168.50.1 | 1.1.1.1 (or campus DNS) |
| Attacker PC | on the outside network (e.g. 192.168.1.20) | outside router | — |

Steps:

1. Identify interfaces with `ip -br link`. In this example, `wlan0` faces campus and `eth1` (the USB adapter) faces the demo switch.
2. Make the machine a router:
   ```bash
   sudo ./backend/scripts/setup_gateway.sh wlan0 eth1 192.168.50.0/24
   ```
3. Configure Snort to watch the protected network on the LAN side:
   ```bash
   sudo ./backend/scripts/setup_snort.sh eth1 192.168.50.0/24 $USER
   ```
4. In `backend/.env`:
   ```ini
   NIDPS_MODE=gateway
   ENABLE_REAL_FIREWALL=true
   SNORT_INTERFACE=eth1
   NIDPS_ALLOWLIST=192.168.50.1
   ```
5. Start Snort and NIDPS:
   ```bash
   sudo ./backend/scripts/start_snort.sh eth1
   cd backend && npm start
   ```
6. Set the victim's static IP as in the table, then check it can reach the internet through the gateway.
7. Tell the attacker PC how to reach the protected network. Use the gateway's WAN address from `ip -br addr`:
   - Linux attacker: `sudo ip route add 192.168.50.0/24 via 192.168.1.10`
   - Windows attacker (administrator PowerShell):

     ```powershell
     route add 192.168.50.0 mask 255.255.255.0 192.168.1.10
     ```

   Check it with `ping 192.168.50.10` from the attacker. Pings are logged as Priority 3 and are not blocked.
8. Attack the victim from the attacker PC: `nmap -sS 192.168.50.10`, repeated `ssh x@192.168.50.10`, or `curl "http://192.168.50.10/?q=union%20select"` against a web server on the victim.
9. Verify with `sudo iptables -L FORWARD -n --line-numbers`: rule 1 must be `NIDPS`. Then run `sudo iptables -L NIDPS -n -v` to see the attacker's DROP rule and its counters. The victim's own internet access keeps working throughout.

Many campus networks drop traffic for routes they don't know about. If step 7 fails, connect the
attacker and the gateway's WAN port to your own small switch or phone hotspot.

**Right before the demo, run the pre-flight check on the gateway.** It changes nothing. It shows
PASS or FAIL with a fix for each item, then prints the attacker's route command using the
gateway's *current* outside address:

```bash
sudo ./backend/scripts/check_gateway.sh wlan0 eth1 192.168.50.0/24 192.168.50.10
```

---

## Gateway mode without a switch: phone hotspot

This needs three machines (attacker, Linux gateway with a USB-Ethernet adapter, victim), one
phone and one Ethernet cable. No switch or router.

```
 Attacker ~~Wi-Fi~~ Phone hotspot ~~Wi-Fi~~ [ NIDPS gateway ] ══cable══ Victim
                     (the "outside")        wlan0       eth1          192.168.50.10
```

The phone simply passes packets between the attacker and the gateway's Wi-Fi. The gateway
forwards them out of `eth1` to the victim. Snort on `eth1` sees the attack, and NIDPS drops the
attacker in `FORWARD` before anything else reaches the victim. Any normal Ethernet cable works
between the gateway and the victim, because modern network ports don't need a crossover cable.

### Set it up

1. Connect the gateway's Wi-Fi and the attacker to the hotspot. Plug the cable between the gateway's adapter and the victim.
2. On the gateway, run `ip -br addr`. It shows the Wi-Fi name and address (for example `wlan0` with 10.42.0.15) and the adapter name (for example `eth1`).
3. On the gateway:
   ```bash
   sudo ./backend/scripts/setup_gateway.sh wlan0 eth1 192.168.50.0/24
   sudo ./backend/scripts/setup_snort.sh eth1 192.168.50.0/24 $USER
   ```
   `setup_gateway.sh` refuses to continue if 192.168.50.0/24 overlaps the hotspot's own range.
   It also saves the `eth1` address as a permanent NetworkManager connection (`nidps-lan`), so it
   can't vanish mid-demo.
4. In `backend/.env`, set `NIDPS_MODE=gateway`, `ENABLE_REAL_FIREWALL=true`, `SNORT_INTERFACE=eth1`,
   `NIDPS_ALLOWLIST=192.168.50.1` and `BLOCK_DURATION_MIN=5`. Then start Snort and NIDPS:
   ```bash
   sudo ./backend/scripts/start_snort.sh eth1
   cd backend && npm start
   ```
5. Give the victim a fixed address: 192.168.50.10, mask 255.255.255.0, gateway 192.168.50.1,
   DNS 1.1.1.1. Use a **Linux victim with SSH**, or run `python -m http.server 80` on it, so there
   is something to see before the block. A Windows victim's firewall drops pings and has no open
   ports by default.

   On a Windows victim, in an administrator PowerShell (check the adapter name with `Get-NetAdapter`):

   ```powershell
   New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.10 -PrefixLength 24 -DefaultGateway 192.168.50.1
   ```
   ```powershell
   Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 1.1.1.1
   ```
6. Run the pre-flight check on the gateway and copy the attacker commands it prints:
   ```bash
   sudo ./backend/scripts/check_gateway.sh wlan0 eth1 192.168.50.0/24 192.168.50.10
   ```
7. Show the dashboard on the **gateway's own screen**. If you open it on the attacker laptop, that
   view stops updating as soon as the attacker is blocked.

### Pre-flight: all 7 must pass before you attack

| # | Where | Check | Expected | If not |
|---|---|---|---|---|
| 1 | Gateway | `sudo ./backend/scripts/check_gateway.sh …` | "All 9 checks passed" | Follow the `fix:` line under each FAIL |
| 2 | Attacker | `ping <gateway hotspot IP>` | Replies | The phone isolates hotspot clients: use a cheap travel router instead |
| 3 | Victim | `ping 1.1.1.1` | Replies (internet through the gateway) | Victim's gateway setting, or re-run `setup_gateway.sh` |
| 4 | Attacker | Add the printed route, then `ping 192.168.50.10` | Replies | Route uses an old gateway address: re-run the check and copy again |
| 5 | Attacker | `curl http://192.168.50.10` or `ssh x@192.168.50.10` | The victim answers | Start the web server or SSH on the victim |
| 6 | Dashboard | Settings tab | Gateway mode, Live firewall, log watcher ACTIVE | `backend/.env`, or Snort not running |
| 7 | Phone | Hotspot settings | Plugged in; "turn off hotspot automatically" disabled | Phones drop idle hotspots |

Then attack: `nmap -sS 192.168.50.10`. Expected result: an alert and an automatic block within
about a second. Checks 4 and 5 now fail from the attacker, while the victim's internet keeps
working. Between rehearsals, run `npm run reset` (or wait 5 minutes for the block to expire),
and re-run the pre-flight check after every hotspot reconnect.

### Why each check is there

| Risk | Covered by |
|---|---|
| Some phones stop hotspot clients talking to each other (it varies by brand and model) | Check 2. The fallback is any Wi-Fi router as the "outside". |
| The phone gives the gateway a different address on each connection | `check_gateway.sh` prints the route with the current address |
| NetworkManager removes the gateway's inside address | `setup_gateway.sh` saves it as the `nidps-lan` connection |
| The hotspot's range clashes with 192.168.50.0/24 | `setup_gateway.sh` refuses; pick another, e.g. 192.168.77.0/24 |
| The presenter's own view gets blocked | Show the dashboard on the gateway (its own addresses are always protected) |
| nmap on a Windows attacker | Install nmap with Npcap; run `nmap -sS` from an administrator terminal |
| A block left over from rehearsal | `BLOCK_DURATION_MIN=5`, `npm run reset` |

---

## Gateway mode on one PC: VirtualBox (no extra hardware)

To rehearse on a single Windows laptop, build the network from virtual machines:

```
 Windows (attacker) ── Host-only network ── [ Ubuntu gateway VM ] ── Internal network "nidps-lan" ── Victim VM
                        192.168.56.x         adapter 1  adapter 2                                     192.168.50.10
```

1. **Gateway VM (Ubuntu):** Adapter 1 is "Host-only Adapter" (outside), Adapter 2 is "Internal Network" named `nidps-lan` (inside).
2. **Victim VM:** one adapter on Internal Network `nidps-lan`. Address 192.168.50.10/24, gateway 192.168.50.1.
3. In the gateway VM, run the same steps as above, using its two adapter names from `ip -br addr`. Then run `check_gateway.sh`. The victim-internet check (pre-flight check 3) will fail here because host-only networks have no internet, and that's fine for the attack demo.
4. The **attacker is Windows itself**: add the route that `check_gateway.sh` prints, then run nmap from an administrator PowerShell.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard not reachable from another PC | `HOST=127.0.0.1`, OS firewall, or Wi-Fi client isolation | Set `HOST=0.0.0.0`, open port 5000, use a switch or hotspot |
| No alerts appear | Snort not running, wrong interface, or NIDPS cannot read the log | `sudo tail -f /var/log/snort/snort.alert.fast`; check `SNORT_LOG_PATH`; log out and in after being added to group `nidps` |
| Alerts appear but no block | IP is protected (allowlist / own address), firewall simulated, or sudo not configured | Settings tab shows the allowlist and firewall mode; check the server log for `Block command failed` |
| `sudo: a password is required` in the log | sudo rule or wrapper missing | Re-run `setup_snort.sh … $USER`, or add the `/etc/sudoers.d/nidps` line above |
| Gateway: victim has no internet | Forwarding/NAT not set, wrong interface names | Re-run `setup_gateway.sh` with the right names; `sysctl net.ipv4.ip_forward` must be 1 |
| Blocks vanish after reboot | Expected for iptables | NIDPS re-applies active blocks on start-up; re-run `setup_gateway.sh` for NAT |
| Locked yourself out | Your own IP was not on the allowlist | Linux console: `sudo iptables -F NIDPS`. Windows (elevated): `Get-NetFirewallRule -DisplayName 'NIDPS-block-*' \| Remove-NetFirewallRule`. Then add your IP to `NIDPS_ALLOWLIST` |
| Windows: "needs Administrator rights" at start | PowerShell not elevated | Right-click PowerShell → *Run as administrator*, or set `ENABLE_REAL_FIREWALL=false` |
| Windows: Snort lists no adapters or cannot open the interface | Npcap missing, or not in WinPcap-compatible mode | Reinstall Npcap with that box ticked; use the adapter **Index** from `snort -W`, not its name |
| Windows: Snort runs but no alerts appear | Wrong adapter, or `SNORT_LOG_PATH` not set to `C:\Snort\log\snort.alert.fast` | Run `check-windows.ps1`; watch the log with `Get-Content C:\Snort\log\snort.alert.fast -Wait` |
