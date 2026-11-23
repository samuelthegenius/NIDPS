# Deploying NIDPS on a campus LAN

NIDPS can run in two modes. Pick one with `NIDPS_MODE` in `backend/.env`.

| | **Host mode** (`host`, default) | **Gateway mode** (`gateway`) |
|---|---|---|
| Protects | The machine NIDPS runs on | Every machine on a small network routed *through* NIDPS |
| Firewall chain | `INPUT` → `NIDPS` | `FORWARD` → `NIDPS` |
| Hardware | One Linux machine (laptop or VM) | A Linux machine with **two** network ports (a USB-Ethernet adapter is fine) + a small switch |
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
| **Windows + WSL2 (default NAT networking)** | Development and the simulator only | WSL2 sits behind a private NAT: other LAN machines cannot reach it, and iptables in WSL protects only the WSL VM, **not Windows**. |
| Windows + WSL2 with `networkingMode=mirrored` | Host mode with care | WSL shares the PC's LAN address, but iptables still only protects services running *inside* WSL. Run the "victim" services (sshd, a web server) in WSL. |

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
ENABLE_REAL_IPTABLES=true
SNORT_LOG_PATH=/var/log/snort/snort.alert.fast
NIDPS_ALLOWLIST=<gateway IP>,<DNS server IP>,<admin PC IP>
DEMO_MODE=true          # keep the simulator for the presentation
```

**Let NIDPS run iptables without being root.** Run `sudo visudo -f /etc/sudoers.d/nidps` and add this line, replacing `student` with your user:

```
student ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables
```

NIDPS calls `sudo -n iptables …` and never runs a shell, so this is the only privilege it needs.

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

## Gateway mode (protect a network behind NIDPS)

```
 Campus LAN / Internet
        │
   wan_if (e.g. wlan0 or eth0, DHCP from campus)
 ┌──────┴──────────────────────────┐
 │  NIDPS gateway (Linux)          │   Snort listens on lan_if
 │  NAT + FORWARD → NIDPS chain    │   NIDPS blocks in FORWARD
 └──────┬──────────────────────────┘
   lan_if (e.g. eth1, USB-Ethernet) 192.168.50.1/24
        │
   small switch ─────────────┬───────────────────┐
                             │                   │
                     Victim PC              Attacker PC
                     192.168.50.10          192.168.50.20
                     (gw 192.168.50.1)      (or on the campus side)
```

| Device | Address | Gateway | DNS |
|---|---|---|---|
| NIDPS `lan_if` | 192.168.50.1/24 | — | — |
| Victim PC | 192.168.50.10/24 | 192.168.50.1 | 1.1.1.1 (or campus DNS) |
| Attacker PC (inside) | 192.168.50.20/24 | 192.168.50.1 | 1.1.1.1 |

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
   ENABLE_REAL_IPTABLES=true
   SNORT_INTERFACE=eth1
   NIDPS_ALLOWLIST=192.168.50.1
   ```
5. Start Snort and NIDPS:
   ```bash
   sudo ./backend/scripts/start_snort.sh eth1
   cd backend && npm start
   ```
6. Set the victim's static IP as in the table, then check it can reach the internet through the gateway.
7. Attack the victim from the attacker PC (`nmap -sS 192.168.50.10`, repeated `ssh` attempts, or `curl "http://192.168.50.10/?q=union%20select"` against a web server on the victim).
8. Verify with `sudo iptables -L FORWARD -n --line-numbers`: rule 1 must be `NIDPS`. Then run `sudo iptables -L NIDPS -n -v` to see the attacker's DROP rule and its counters.

A note on traffic between two inside machines: two machines plugged into the same switch talk to each other directly, without passing through the gateway. To show prevention between them, put the attacker on the **campus side** (WAN) and attack the victim through the gateway, or give each machine its own NIDPS port.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard not reachable from another PC | `HOST=127.0.0.1`, OS firewall, or Wi-Fi client isolation | Set `HOST=0.0.0.0`, open port 5000, use a switch or hotspot |
| No alerts appear | Snort not running, wrong interface, or NIDPS cannot read the log | `sudo tail -f /var/log/snort/snort.alert.fast`; check `SNORT_LOG_PATH`; log out and in after being added to group `nidps` |
| Alerts appear but no block | IP is protected (allowlist / own address), firewall simulated, or sudo not configured | Settings tab shows the allowlist and firewall mode; check the server log for `Block command failed` |
| `sudo: a password is required` in the log | sudoers rule missing | Add the `/etc/sudoers.d/nidps` line above |
| Gateway: victim has no internet | Forwarding/NAT not set, wrong interface names | Re-run `setup_gateway.sh` with the right names; `sysctl net.ipv4.ip_forward` must be 1 |
| Blocks vanish after reboot | Expected for iptables | NIDPS re-applies active blocks on start-up; re-run `setup_gateway.sh` for NAT |
| Locked yourself out | Your own IP was not on the allowlist | From the console: `sudo iptables -F NIDPS`, then add your IP to `NIDPS_ALLOWLIST` |
