# SRID

**SSH Real-time Intrusion Detector**

A log-based SSH intrusion detection system built for a Docker-based lab.
It detects brute-force and suspicious SSH access attempts using rule-based analysis.

## Summary

SRID runs in a Docker Compose lab:
**attack → target(SSH server) → detection(SRID)**

- Parses SSH logs
- Classifies events (EventType)
- Aggregates per IP/User state
- Triggers alerts (AlertType) with cooldown/window rules

## Project Purpose

This project was built to design and implement a state-based
log-driven intrusion detection system from scratch.

The goal was to:

- Design rule-based alert logic
- Build an isolated Docker security lab

## Architecture

Docker Compose containers:

- **attack**: runs Hydra / SSH attempts
- **target**: SSH server (log source)
- **detection**: collects logs, analyzes events, and raises alerts

## Detection Logic

### EventType

- FAIL_PW
- INVALID_USER
- PREAUTH
- LOGIN_SUCCESS

### AlertType

- IP_FAIL_PW
- IP_INVALID_USER
- IP_PREAUTH
- IP_BRUTEFORCE_SUCCESS
- IP_ATTACK
- USER_FAIL_PW
- USER_BRUTEFORCE_SUCCESS
- USER_MULTI_IP_TO_SINGLE_USER
- USER_ROOT_TRY
- USER_ROOT_SUCCESS

### Rule (config)

- `window_s`: depends on AlertType
- `ttl_s`: 3600
- `cooldown_s`: 120
  - Change: `Analyzer.DEFAULT_COOLDOWNS` in `analyzer.py`

## DataManager

- Manages global runtime state
- Maintains:
  - IP table
  - User table
  - Alert table

## Processing Pipeline

1. **Parser**  
   SSH log line → parse & classify EventType → `RawLogEvent`
2. **Dispatcher**  
   `RawLogEvent` → update `ip_table` and `user_table`
3. **Analyzer**  
   Apply rules → check cooldown/window → raise `Alert`

## How to Run

### 1. Build and start the containers

```bash
docker compose up --build
```

### 2. Run the detection server

Open a new terminal and enter the detection server container.

```bash
docker exec -it srid-detection /bin/bash
```

Then run the main script.

```bash
python3 main.py
```

### 3. Run the attack scenario

Open another terminal and enter the attack server container.

```bash
docker exec -it srid-attack /bin/bash
```

Run Hydra to generate SSH login attempts against the target server.

```bash
hydra -L data/user.txt -P data/pass.txt ssh://srid-target
```

### 4. Check the detection result

The detection server monitors the SSH log file and prints an alert when repeated authentication failures are detected.

```text
[MEDIUM] SECURITY ALERT DETECTED
Type    : IP_FAIL_PW
Target  : 172.xx.xx.xx
Evidence: 172.xx.xx.xx: 5 fail_count detected
```
