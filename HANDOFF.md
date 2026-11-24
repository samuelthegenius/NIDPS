# Start here

Welcome. This file gets you from zero to running and understanding NIDPS
without anyone having to walk you through it.

## 1. What this is (2 minutes)

NIDPS is a final-year project: a **Network Intrusion Detection and Prevention System**.

- **Snort** inspects network traffic and writes an alert line for every attack it recognises.
- **The NIDPS backend** (Node.js) reads those lines, stores them, and **blocks attackers** with
  the firewall (iptables on Linux, Windows Firewall on Windows), either immediately (high
  severity) or after repeated attempts (medium severity).
- **The dashboard** (React) shows everything live and lets an admin block, unblock and triage.

It can protect the machine it runs on (**host mode**) or a small network behind it (**gateway mode**).

## 2. Run it on your laptop (10 minutes)

You need Node.js 18+ and Git, on Windows, Linux or macOS. Snort and PostgreSQL are **not** needed for this.

```bash
git clone <repository URL>
cd <repository folder>/backend
npm install
npm run setup            # choose an admin password (at least 10 characters)
cd ../frontend
npm install
npm run build
cd ../backend
npm start
```

Open http://localhost:5000, sign in as `admin`, and click **Simulate Attack → Apache Log4j → Inject**.
The alert appears and the attacker is blocked within a second. Then try *SSH Brute Force* five times.

Run the tests with `cd backend && npm test` (and `npm run test:scripts` for the shell scripts, from Git Bash or Linux). They should all pass.

## 3. Read in this order (about 1 hour)

1. [README.md](README.md): overview and commands.
2. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how one attack flows through the code, and why it was designed this way.
3. The code itself, in the order an alert travels:
   `backend/src/services/snortParser.js` → `detector.js` → `firewall/index.js` → `routes/api.js` → `frontend/src/App.jsx`.
   Each has a matching test in `backend/test/`, and the tests are the quickest way to see what each part does.
4. [docs/SECURITY.md](docs/SECURITY.md): the threat model and what was fixed.
5. [docs/LAN_DEPLOYMENT.md](docs/LAN_DEPLOYMENT.md): running it for real on a LAN.
6. [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md): the presentation, minute by minute, with likely examiner questions.

The original design and the build plan are in `docs/superpowers/` (`specs/` and `plans/`), if you
want to see *why* each change was made.

## 4. Where things live

```
backend/
  src/server.js               entry point (wires everything together)
  src/app.js                  HTTP app, security headers, serves the dashboard
  src/config/settings.js      every .env setting, validated
  src/services/               parser, detector, firewall engine, log watcher, events
  src/store/                  database layer (PostgreSQL + in-memory)
  src/auth/                   password hashing, sessions, login rate limit
  src/routes/                 REST API, login, live events, simulator
  scripts/                    setup, reset, Snort + gateway + certificate scripts
  db/init.sql                 database schema
  test/                       automated tests (npm test)
  .env.example                every setting, documented
frontend/src/                 React dashboard
docs/                         architecture, LAN deployment, demo script, security
docker-compose.yml            PostgreSQL (optional)
  scripts/windows/            Windows: Snort setup/start, pre-flight check, autostart
  scripts/snort/nidps.rules   the demo Snort rules (used by Linux and Windows)
```

## 5. Working on it together

- Keep `backend/.env` **out of Git**. It holds the password hash and session secret, and `.gitignore` already excludes it. Each person runs `npm run setup` on their own machine.
- Work on a branch, run `npm test` before pushing, and open a pull request for the other person to review.
- If you change a setting, add it to `backend/.env.example` and `src/config/settings.js`, and test it in `test/settings.test.js`.

## 6. Open items / known limitations

- The PostgreSQL code path has passed its tests only against the in-memory store so far. Once Docker is
  running: `docker compose --env-file backend/.env up -d`, then
  `TEST_DATABASE_URL=postgres://postgres:<password>@localhost:5432/nidps_db npm test`.
  Note that this empties the tables.
- The gateway and Snort setup scripts were syntax-checked but have not yet been run on a real dual-NIC machine.
- Host mode runs natively on Windows (Snort for Windows + Windows Firewall) and on Linux (iptables).
  Gateway mode is Linux only. The live Windows Firewall path is covered by tests with a fake `netsh`
  but has not yet been run elevated on a real Windows machine with Snort installed:
  run `backendscriptswindowscheck-windows.ps1` and one real block before the demo.
- See "Remaining risks" in docs/SECURITY.md.
