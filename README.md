# fex

Tool to run scripts and commands in batch on hosts managed by **CrowdStrike Falcon**, using the **Real-Time Response (RTR)** API. You can target a single device, all devices in the tenant, search by name, or filter by platform (Windows, Mac, Linux), with batch execution and consolidated reports.

I find it odd that Falcon provides SDK support but not a ready-made binary—practically any ops team could use a tool like this, both for batch machine management and for incident response. fex is an attempt to fill that gap in a simple way.

## Requirements

- Python 3.x
- CrowdStrike Falcon account with RTR and host-listing permissions

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Create a `config.json` file in the project root with your Falcon API credentials:

```json
{
  "falcon_credentials": {
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET"
  }
}
```

> **Note:** `config.json` is in `.gitignore` so credentials are not committed. You can add an example (e.g. `config.example.json`) to the repo to document the structure.

## Usage

### List devices

```bash
# All devices (ID, hostname, platform, status)
python3 fex.py --list
```

### Run a script

```bash
# On a single host (Device ID)
python3 fex.py --device <DEVICE_ID> --script <SCRIPT_PATH>

# On all hosts in the tenant (in batches)
python3 fex.py --all --script <SCRIPT_PATH> --batch-size 200

# Search by name and run
python3 fex.py --search <NAME> --script <SCRIPT_PATH>

# Exact computer name
python3 fex.py --computer-name <EXACT_NAME> --script <SCRIPT_PATH>

# Filter by platform (Mac, Windows, Linux, etc.)
python3 fex.py --platform Windows --script script.ps1
```

### Script directory

```bash
# Run all scripts in a directory (scripts split by platform: .ps1/.bat on Windows, .sh on Mac/Linux)
python3 fex.py --all --script-dir <SCRIPT_DIR> --batch-size 200
```

### Direct command

```bash
# Command on all hosts
python3 fex.py --all --command "ls -la"

# Command on hosts matching search
python3 fex.py --search <NAME> --command "whoami"
```

### Arguments and hostname

```bash
# Arguments for the script
python3 fex.py --all --script script.ps1 --args "arg1 arg2"

# Pass hostname as a parameter to the script
python3 fex.py --all --script script.ps1 --hostname "HOSTNAME_PLACEHOLDER"
```

## Main options

| Option | Description |
|--------|-------------|
| `--device <ID>` | Run only on the device with the given Device ID |
| `--all` | Run on all devices in the tenant |
| `--search <NAME>` | Search for devices whose hostname contains the text |
| `--computer-name <NAME>` | Search for device by exact name and run |
| `--platform <PLATFORM>` | Filter by platform (e.g. Windows, Mac, Linux) |
| `--list` | List all devices (no execution) |
| `--script <PATH>` | Path to a script or script directory |
| `--script-dir <DIR>` | Directory of scripts (automatic split by platform) |
| `--command "CMD"` | Run a raw command on the host |
| `--batch-size N` | Number of IDs per batch (default: 500) |
| `--args "..."` | Arguments passed to scripts |
| `--hostname "..."` | Hostname parameter value for the script |

## Logs and cache

### rtr.log

RTR execution log file, created in the project root. It is **cleared at the start of each run** (except when using only `--list`). It records:

- **Flow events:** batch session start, count of devices with and without session, script/command success or failure, consolidated report generation.
- **Errors and retries:** API failures, offline devices or failed sessions, and retry attempts with backoff.
- **Per-device output:** for each host, device ID (abbreviated), hostname, command/script run, stdout, stderr, and status.

Each line uses standard logging format: `timestamp - level - message`. The same log is written to the file and to the terminal (stdout).

### execution.log

Detailed output per device/command, used as input for the **consolidated report** shown at the end. When a run produces `execution.log`, a consolidated report is generated in the terminal.

### Device cache (devices_cache.json)

Local cache of the tenant’s device list, created in the project root. It reduces Falcon API calls by reusing the list already fetched.

- **Validity:** the cache is considered valid for **1 hour** (configurable in code via `CACHE_MAX_AGE_HOURS`). After that, the next operation that needs the list (e.g. `--list`, `--all`, `--search`) fetches from the API and overwrites the cache.
- **Contents:** JSON file with `timestamp` (generation time) and `devices` (array of id, hostname, platform, status, etc.).
- **Usage:** when listing devices or building the host set for execution, fex checks for a valid cache; if present, it uses the file instead of calling the API.
- The file is in `.gitignore` and should not be committed (it can be large and is environment/tenant-specific).

## License

**Do What the Fuck You Want To** — [WTFPL](https://en.wikipedia.org/wiki/WTFPL).
