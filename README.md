# log-enricher

Apache log security tool: parse logs, detect suspicious IPs, enrich with IP intelligence from ipinfo.io API

## Overview

This is a small security tool that:
1. Reads an Apache access log file
2. Uses regex to extract IP addresses, HTTP methods, paths, and status codes
3. Identifies suspicious IPs based on behavior
4. Uses the ipinfo.io API to gather intelligence about those IPs
5. Produces a final enriched security report

## Features

- **Streaming file reading**: Efficiently processes large log files line-by-line
- **Regex-based parsing**: Safely extracts fields without crashing on malformed lines
- **Suspicious IP detection**:
  - >= 5 HTTP 401 or 403 responses
  - >= 10 HTTP 404 responses
  - Access to sensitive paths (e.g., /admin, /wp-login, /.git, /.env, /phpmyadmin)
- **IP enrichment**: Queries ipinfo.io for country, organization, and city information
- **JSON export**: Optional JSON report output
- **Error handling**: Graceful handling of API failures and malformed data

## Installation

### Requirements
- Python 3.7+
- `requests` library

### Setup

```bash
# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python log_enricher.py <path-to-logfile>
```

### With JSON Output

```bash
python log_enricher.py <path-to-logfile> --json-out report.json
```

### Example

```bash
python log_enricher.py access.log --json-out security_report.json
```

## Output Format

### Human-Readable Report

```
Lines processed: 120
Parse failures: 3
Suspicious IP Report:
IP: 198.51.100.77
  401 count: 12
  403 count: 0
  404 count: 0
  Sensitive paths: /wp-login.php
  Country: US
  City: San Francisco
  Org: AS13335 Cloudflare, Inc.

IP: 203.0.113.45
  401 count: 3
  403 count: 0
  404 count: 5
  Sensitive paths: /admin, /.git/config
  Country: DE
  City: Berlin
  Org: AS12345 Example Hosting
```

### JSON Report

See the report.json file for detailed structure.

## Technical Details

- **Log Pattern**: Matches standard Apache combined log format
- **Timeout**: 5-second timeout for API calls
- **Error Handling**: Graceful degradation on API failures; missing IPs are still reported
- **Private IPs**: RFC1918 private addresses are filtered out (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

## Configuration

Edit thresholds in `log_enricher.py`:

```python
MAX_401_403 = 5    # Suspicious if 5+ 401/403 responses
MAX_404 = 10       # Suspicious if 10+ 404 responses
SENSITIVE_PATHS = [...]  # Add/remove paths as needed
```

MIT License

## Author

Ruben4TPIFI
