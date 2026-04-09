# VirusTotal Bulk URL Scanner

A Python-based bulk URL scanning tool that integrates with the VirusTotal API and generates analyst-friendly reports in PDF, JSON, and CSV.

## What This Project Does

This script helps you triage many URLs quickly by:

- Accepting bulk URLs from terminal paste or input files
- Normalizing and deduplicating URLs
- Querying VirusTotal URL intelligence endpoints
- Handling not-found URL lookups by submitting fresh analysis
- Classifying threats with weighted detection logic
- Generating non-overwriting reports
- Showing ETA and progress while scanning

## Key Features

- Bulk URL input from terminal (paste list, then finish with Ctrl+Z + Enter on Windows)
- Optional URL input from TXT/CSV file
- URL normalization (adds http:// when scheme is missing)
- Duplicate removal while preserving input order
- API retry logic with backoff for transient failures
- Rate-limit-aware API pacing
- ETA based on lookups per minute
- PDF report generation with per-URL summary and vendor detections
- Optional JSON/CSV export for automation
- Safe output naming that never overwrites existing reports

## Project Structure

- virustotal.py: Main scanner and report generator
- README.md: Project documentation

## Requirements

- Python 3.8+
- VirusTotal API key

Python packages used:

- requests
- reportlab

## Installation

1. Create and activate a virtual environment (recommended).
2. Install dependencies:

```bash
pip install requests reportlab
```

## How Input Works

You have two ways to provide URLs:

1. Terminal paste mode (default or with --stdin-urls)
2. File mode (with --urls-file)

### Terminal Paste Mode (Windows)

1. Run the script.
2. Paste URLs (one per line).
3. Press Ctrl+Z, then Enter to finish input.

Example:

Simply:
```powershell
python .\virustotal.py --api-key YOUR_API_KEY
```

```powershell
python .\virustotal.py --api-key YOUR_API_KEY --stdin-urls --pdf VirusTotal_Report.pdf --json VirusTotal_Report.json --csv VirusTotal_Report.csv
```

### File Mode

```powershell
python .\virustotal.py --api-key YOUR_API_KEY --urls-file urls.txt --pdf VirusTotal_Report.pdf --json VirusTotal_Report.json --csv VirusTotal_Report.csv
```

Supported file types for --urls-file:

- .txt (one URL per line)
- .csv (URL values in cells)

## CLI Arguments

- --api-key: VirusTotal API key (or set VT_API_KEY env var)
- --urls-file: Path to TXT/CSV with URLs
- --stdin-urls: Read URLs from terminal paste input
- --pdf: Output PDF path
- --json: Optional JSON output path
- --csv: Optional CSV output path
- --rate-limit-per-minute: API request pacing limit (default: 4)
- --lookups-per-minute: Lookup-rate model for ETA/progress (default: 4)
- --force-rescan: Always submit URL for fresh analysis
- --verbose: Enable debug logs

## Rate Limiting and ETA

The script separates two timing concepts:

1. API pacing
- Controlled by --rate-limit-per-minute
- Prevents rapid API calls and helps stay within limits

2. Runtime estimate
- Controlled by --lookups-per-minute
- ETA model assumes 1 lookup = 1 URL for progress estimation

Estimated total runtime is computed as:

estimated_seconds = (total_urls * 60) / lookups_per_minute

Remaining runtime updates after each URL is processed.

## Handling Not Found URL Lookups

If VirusTotal returns not found for a URL report lookup, the script:

1. Treats it as a normal missing lookup state (not a fatal error)
2. Submits the URL for analysis
3. Polls analysis status
4. Fetches the final URL report

## Output and Report Naming

The script prevents overwriting existing files.

If an output filename already exists, it creates the next available name:

- VirusTotal_Report.pdf
- VirusTotal_Report 1.pdf
- VirusTotal_Report 2.pdf

Same behavior applies to JSON and CSV outputs.

## Report Contents

### PDF

- Input URL and normalized URL
- Processing status
- Threat category
- Analysis stats:
  - malicious
  - suspicious
  - harmless
  - undetected
- Top vendor detections

### JSON

Machine-readable full results for each URL.

### CSV

Flat table export for spreadsheet and SIEM workflows.

## Example Commands

Use API key directly:

Simply:
```powershell
python .\virustotal.py --api-key YOUR_API_KEY
```

```powershell
python .\virustotal.py --api-key YOUR_API_KEY --stdin-urls --pdf VirusTotal_Report.pdf --json VirusTotal_Report.json --csv VirusTotal_Report.csv --rate-limit-per-minute 4 --lookups-per-minute 4
```

Use environment variable for API key:

```powershell
$env:VT_API_KEY="YOUR_API_KEY"
python .\virustotal.py --stdin-urls --pdf VirusTotal_Report.pdf --json VirusTotal_Report.json --csv VirusTotal_Report.csv
```

Force fresh scans:

```powershell
python .\virustotal.py --api-key YOUR_API_KEY --stdin-urls --force-rescan
```

## Logging and Progress

During execution, logs include:

- API pacing summary
- ETA model details
- Estimated total runtime
- Per-URL processing progress
- Requests made so far
- Elapsed and estimated remaining time
- Final duration and total API request count

## Security Notes

- Do not hardcode API keys in source code.
- Prefer environment variables or secure secret storage.
- Some submitted URLs may be sensitive; follow your org policy before scanning.

## Limitations

- Final runtime depends on API responsiveness and analysis completion timing.
- ETA is a model based on lookup rate, not a guaranteed finish time.
- VirusTotal response fields can vary depending on URL analysis availability.

## Future Improvements

- Batch resume/retry checkpoint support
- Domain-level aggregation and summary charting
- HTML report export with visual indicators
- Optional asynchronous processing strategy

## License

Add your preferred license (for example: MIT) before publishing.

## Author

Add your name, profile, and contact links before pushing to GitHub.
