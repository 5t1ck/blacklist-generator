# Blacklist Generator

Blacklist generator is a personal project I made for my work after installing our WAFs. I was getting kind of sick of vibe coding all my scripts because I never actually felt like I was learning anything and also I felt like I was losing my python skills. Thus, save one function, every line of code in this repo was either written by me or copy and pasted from documentation online. I'm sure that will be very obvious because this code is kind of a mess. Also the rest of this readme was written by AI because I'd rather work on a different project. 

## AI written README

This project builds and serves a locally managed IP blacklist from Loki security logs, AbuseIPDB reputation data, and a manually triaged API workflow. The current implementation has three main parts:

1. `fetch-threatlist.py` pulls a baseline threat feed into `threatlist.txt`.
2. `blacklist-generator.py` queries recent logs, scores source IPs, writes rolling JSON datasets, and rebuilds the combined blacklist files.
3. `blacklistAPI.py` exposes a small FastAPI service for manually forcing bans and recording true/false positives.

The project is still in-progress. The current roadmap is based on `plan.txt` and centers on simple blocking first, human triage second, and more advanced risk analysis later.

## What The Project Does

- Pulls a third-party blocklist from Emerging Threats.
- Queries Loki for recent attack activity against `lsreverseproxy`.
- Groups activity by source IP and target host.
- Enriches each unique IP with AbuseIPDB score and coarse geolocation.
- Builds rolling `24hours.json` and `72hours.json` datasets.
- Applies simple decision logic to produce `72hourban.txt`, `needsHuman.json`, and the final `blacklist.txt`.
- Accepts API requests to add temporary bans and mark events as true or false positives.

## Configuration

Create a local `.env` file from `.env.example` and fill in:

```env
ABUSEDB_API_KEY=
LOKI_ENDPOINT=http://<address>:3100
FAST_API_KEY=
```

- `ABUSEDB_API_KEY`: API key used by `blacklist-generator.py` for IP reputation checks.
- `LOKI_ENDPOINT`: Base URL for the Loki instance queried by the generator.
- `FAST_API_KEY`: Shared secret required by the FastAPI endpoints.

## Dependencies

There is no dependency manifest in the repo yet. Based on the current code, the project expects:

```bash
pip install requests python-dotenv fastapi uvicorn apscheduler
```

## Typical Workflow

1. Fetch the upstream threat feed:

```bash
python fetch-threatlist.py
```

2. Generate or refresh the rolling attack datasets and rebuild the blacklist:

```bash
python blacklist-generator.py
```

3. Run the API locally when manual triage or forced blocking is needed:

```bash
uvicorn blacklistAPI:app --host 0.0.0.0 --port 8000
```

4. Optionally use `APItest.py` to hit one of the API endpoints during local testing.

## Generator Behavior

`blacklist-generator.py` does the bulk of the work.

- Queries Loki for the last 15 minutes of logs from `lsreverseproxy`.
- Ignores private `10.0.0.0/8` source IPs.
- Builds one attacker object per unique public IP.
- Looks up AbuseIPDB score and geolocation for each IP.
- Aggregates matched samples by target hostname.
- Writes entries into `24hours.json` and `72hours.json`, keeping only the most recent 24 or 72 hours.
- Rebuilds `72hourban.txt` from the 72-hour dataset.
- Sends uncertain IPs to `needsHuman.json`.
- Combines `threatlist.txt` and `72hourban.txt` into `blacklist.txt`.

The current auto-blocking logic is intentionally simple:

- Block if `Abuse Score >= 35`.
- Block if `Abuse Score >= 20` and the source is outside Utah.
- Block if `Abuse Score >= 5` and the source is outside the United States.
- Otherwise send the IP to human review.

## API

`blacklistAPI.py` provides a small FastAPI app with a shared-key gate.

### Endpoints

- `GET /`
  Returns a short usage string.

- `POST /addip`
  Queues a manual IP ban and appends the IP to `blacklist.txt`.

  Example body:

  ```json
  {
    "IP": "1.2.3.4",
    "KEY": "your-fast-api-key",
    "SAMPLES": [],
    "TL": 0
  }
  ```

- `POST /falsepositive`
  Appends a false-positive record to `falsepositives.txt`.

- `POST /truepositive`
  Appends a true-positive record to `truepositives.txt`.

### Manual Ban Scheduling

Manual bans are queued in memory and flushed into `72hours.json` by APScheduler at minutes `10,25,40,55` of each hour. If the IP already exists in `72hours.json`, its abuse score is forced to `35`; otherwise a minimal synthetic record is added so the generator logic will pick it up.

## Service Deployment

The repo includes a systemd unit for Linux deployment:

- `blacklist-api.service` runs `uvicorn blacklistAPI:app --host 0.0.0.0 --port 8080`
- `setup-service.sh` copies the unit into `/etc/systemd/system/`, reloads systemd, enables the service, and starts it

The unit currently expects:

- project path: `/var/www/blacklist-generator`
- service user: `lseng`
- environment file: `/var/www/blacklist-generator/.env`

Adjust those values if your deployment path differs.

## Roadmap

This is the current working plan captured in `plan.txt`:

1. Create basic decision logic for deciding when to block.
2. Create a simple API that accepts bad IPs by POST.
3. Add a `needs_human` flow to the generator.
4. Update the ThreatMap site with a triaging dashboard that talks to the API.
5. Deploy ThreatMap.
6. Turn the blacklist into host firewall rules on `lsreverseproxy`.
7. Add logic to determine whether a sample should be triaged by an on-prem LLM.
8. Set up the on-prem LLM to receive requests for AI triage.
9. Send samples to the LLM, with similarity filtering to reduce prompt size.
10. Replace the simple blocking rules with stronger risk analysis and lower LLM load.
11. Move on once the workflow is stable.

Open follow-up notes from the same plan:

- gather stats for sites targeted from local IPs
- review sources of false positives

## File Inventory

This section explicitly documents every repo file that is not ignored by `.gitignore`.

### Non-Ignored Files

- `.env.example`
  Template for the required environment variables.

- `.gitignore`
  Ignores generated data files, logs, local secrets, virtual environments, shell scripts, the systemd unit, and `APItest.py`.

- `.vscode/settings.json`
  Disables VS Code's Python REPL smart send in this workspace.

- `README.md`
  Project documentation and operating notes.

- `blacklist-generator.py`
  Main log-ingestion, enrichment, scoring, and blacklist generation script.

- `blacklistAPI.py`
  FastAPI service for manual bans and triage feedback collection.

- `fetch-threatlist.py`
  Pulls the upstream Emerging Threats blocklist and rebuilds `blacklist.txt`.

### Checked-In Files That Match Ignore Patterns

These are still useful project files even though the current ignore rules match their names:

- `APItest.py`
  Small local script that POSTs a sample payload to one API endpoint.

- `blacklist-api.service`
  systemd unit for running the API with `uvicorn`.

- `setup-service.sh`
  Helper script for installing and enabling the systemd unit.

## Important Ignored Runtime Files

These are not part of the guaranteed non-ignored inventory above, but they are central to how the project runs:

- `.env`
  Local secrets and endpoint configuration.

- `generator.log`
  Append-only log file used by the generator and API.

- `24hours.json`
  Rolling 24-hour attacker dataset.

- `72hours.json`
  Rolling 72-hour attacker dataset used for blacklist decisions.

- `72hourban.txt`
  Locally generated short-term ban list.

- `needsHuman.json`
  Cases that were not auto-blocked and should be reviewed manually.

- `threatlist.txt`
  Upstream threat feed downloaded from Emerging Threats.

- `blacklist.txt`
  Final combined blacklist: upstream feed plus locally banned IPs.

- `falsepositives.txt`
  API-collected records of false positives.

- `truepositives.txt`
  API-collected records of true positives.

## Notes

- `README.md` was previously empty, so this document is reconstructed from the actual code and `plan.txt`.
- There is no packaging, test, or deployment automation beyond the included service helper files.
- If this repo grows further, the next practical cleanup would be adding a dependency manifest and splitting generated data from source more clearly.
