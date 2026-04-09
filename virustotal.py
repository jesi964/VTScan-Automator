import argparse
import base64
import csv
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from xml.sax.saxutils import escape


DEFAULT_PDF_PATH = "VirusTotal_Report.pdf"
DEFAULT_JSON_PATH = "VirusTotal_Report.json"
DEFAULT_CSV_PATH = "VirusTotal_Report.csv"

API_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class VTConfig:
    api_key: str
    request_timeout: int = 30
    inter_request_delay: float = 3.0
    max_retries: int = 5
    analysis_poll_interval: float = 5.0
    analysis_poll_attempts: int = 12
    top_detections_limit: int = 8
    force_rescan: bool = False
    rate_limit_per_minute: int = 4
    lookups_per_minute: int = 4


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def safe_text(value: object) -> str:
    return escape(str(value))


def normalize_url(raw_url: str) -> Optional[str]:
    candidate = (raw_url or "").strip()
    if not candidate:
        return None

    if not candidate.startswith(("http://", "https://")):
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    if not parsed.netloc:
        return None

    return candidate


def read_urls_from_file(file_path: str) -> List[str]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"URL input file not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()
    urls: List[str] = []

    if ext == ".csv":
        with open(file_path, "r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                for value in row:
                    value = value.strip()
                    if value and not value.startswith("#"):
                        urls.append(value)
    else:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                value = line.strip()
                if value and not value.startswith("#"):
                    urls.append(value)

    return urls


def parse_urls_from_text(text: str) -> List[str]:
    urls: List[str] = []
    for line in text.splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            urls.append(value)
    return urls


def read_urls_from_stdin() -> List[str]:
    print("Paste bulk URLs (one per line).")
    print("Finish with Ctrl+Z then Enter on Windows (Ctrl+D on Linux/macOS).")
    payload = sys.stdin.read()
    return parse_urls_from_text(payload)


def format_duration(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def resolve_non_overwriting_path(path: str) -> str:
    if not os.path.exists(path):
        return path

    directory, filename = os.path.split(path)
    stem, ext = os.path.splitext(filename)
    counter = 1
    while True:
        candidate = os.path.join(directory, f"{stem} {counter}{ext}")
        if not os.path.exists(candidate):
            return candidate
        counter += 1


def encode_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


class VirusTotalClient:
    def __init__(self, config: VTConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": config.api_key})
        self.request_count = 0
        self._last_request_monotonic = 0.0

    def _throttle(self) -> None:
        if self.config.rate_limit_per_minute <= 0:
            return

        min_interval = 60.0 / float(self.config.rate_limit_per_minute)
        if self._last_request_monotonic <= 0:
            return

        elapsed = time.monotonic() - self._last_request_monotonic
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

    def _request(
        self,
        method: str,
        endpoint: str,
        allow_not_found: bool = False,
        **kwargs,
    ) -> Optional[dict]:
        url = f"{API_BASE}{endpoint}"
        retries = self.config.max_retries
        backoff = self.config.inter_request_delay

        for attempt in range(1, retries + 1):
            try:
                self._throttle()
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.config.request_timeout,
                    **kwargs,
                )
                self.request_count += 1
                self._last_request_monotonic = time.monotonic()
            except requests.RequestException as exc:
                logging.warning(
                    "Request failed (%s %s), attempt %s/%s: %s",
                    method,
                    endpoint,
                    attempt,
                    retries,
                    exc,
                )
                if attempt == retries:
                    return None
                time.sleep(backoff)
                backoff *= 2
                continue

            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_time = float(retry_after) if retry_after and retry_after.isdigit() else backoff
                logging.warning("Rate limit hit for %s. Waiting %.1f seconds.", endpoint, wait_time)
                time.sleep(wait_time)
                backoff *= 2
                continue

            if 500 <= response.status_code < 600:
                logging.warning(
                    "Server error %s on %s, attempt %s/%s",
                    response.status_code,
                    endpoint,
                    attempt,
                    retries,
                )
                if attempt == retries:
                    return None
                time.sleep(backoff)
                backoff *= 2
                continue

            if response.status_code not in (200, 201):
                if allow_not_found and response.status_code == 404:
                    logging.debug("Not found yet for %s %s", method, endpoint)
                    return None
                logging.error(
                    "API request failed: %s %s => %s %s",
                    method,
                    endpoint,
                    response.status_code,
                    response.text,
                )
                return None

            try:
                return response.json()
            except ValueError:
                logging.error("Invalid JSON response from %s", endpoint)
                return None

        return None

    def get_url_report(self, normalized_url: str) -> Optional[dict]:
        url_id = encode_url_id(normalized_url)
        return self._request("GET", f"/urls/{url_id}", allow_not_found=True)

    def submit_url(self, normalized_url: str) -> Optional[str]:
        payload = {"url": normalized_url}
        response = self._request("POST", "/urls", data=payload)
        if not response:
            return None

        data = response.get("data", {})
        analysis_id = data.get("id")
        if not analysis_id:
            logging.error("Submit URL response missing analysis id for %s", normalized_url)
            return None

        return analysis_id

    def wait_for_analysis(self, analysis_id: str) -> bool:
        for attempt in range(1, self.config.analysis_poll_attempts + 1):
            response = self._request("GET", f"/analyses/{analysis_id}")
            if not response:
                time.sleep(self.config.analysis_poll_interval)
                continue

            status = (
                response.get("data", {})
                .get("attributes", {})
                .get("status", "")
                .lower()
            )
            if status == "completed":
                return True

            logging.debug(
                "Analysis %s status is '%s' (attempt %s/%s)",
                analysis_id,
                status,
                attempt,
                self.config.analysis_poll_attempts,
            )
            time.sleep(self.config.analysis_poll_interval)

        logging.warning("Analysis %s did not complete in polling window.", analysis_id)
        return False


def classify_threat_weighted(
    analysis_results: Dict[str, dict], stats: Dict[str, int]
) -> Tuple[str, Dict[str, float]]:
    category_keywords = {
        "Phishing": {
            "phish": 4.0,
            "fraud": 3.0,
            "scam": 2.5,
            "credential": 3.0,
        },
        "Malware": {
            "malware": 4.0,
            "trojan": 4.0,
            "ransom": 4.5,
            "worm": 3.5,
            "virus": 3.0,
            "backdoor": 4.0,
            "botnet": 3.5,
        },
        "Spyware": {
            "spyware": 4.0,
            "keylog": 4.0,
            "stealer": 3.5,
            "infostealer": 4.0,
            "adware": 2.5,
        },
        "Suspicious": {
            "suspicious": 2.0,
            "heuristic": 2.0,
            "untrusted": 1.5,
            "risk": 1.5,
            "potentially unwanted": 1.5,
            "pua": 1.5,
        },
    }

    scores: Dict[str, float] = {k: 0.0 for k in category_keywords}

    for vendor_data in analysis_results.values():
        result = (vendor_data.get("result") or "").lower()
        if not result:
            continue

        for category, keywords in category_keywords.items():
            for token, weight in keywords.items():
                if token in result:
                    scores[category] += weight

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    scores["Malware"] += malicious * 0.7
    scores["Phishing"] += malicious * 0.5
    scores["Suspicious"] += suspicious * 0.8
    if undetected > 0 and malicious == 0 and suspicious == 0:
        scores["Suspicious"] += 0.2

    top_category = max(scores, key=scores.get)
    if malicious == 0 and suspicious == 0 and scores[top_category] < 1.5:
        return "Clean", scores
    if scores[top_category] < 2.5 and malicious == 0:
        return "Suspicious", scores

    return top_category, scores


def extract_top_detections(
    analysis_results: Dict[str, dict], limit: int
) -> List[Dict[str, str]]:
    detections: List[Dict[str, str]] = []
    for vendor, data in analysis_results.items():
        result = data.get("result")
        if not result:
            continue
        detections.append(
            {
                "vendor": vendor,
                "category": str(data.get("category", "unknown")),
                "result": str(result),
            }
        )

    detections.sort(key=lambda x: (x["category"] != "malicious", x["vendor"].lower()))
    return detections[:limit]


def analyze_url(client: VirusTotalClient, raw_url: str, config: VTConfig) -> Dict[str, object]:
    normalized_url = normalize_url(raw_url)
    if not normalized_url:
        return {
            "input_url": raw_url,
            "url": raw_url,
            "status": "invalid",
            "error": "Invalid URL format",
        }

    logging.info("Analyzing URL: %s", normalized_url)

    report = None
    if not config.force_rescan:
        report = client.get_url_report(normalized_url)

    if config.force_rescan or not report:
        analysis_id = client.submit_url(normalized_url)
        if not analysis_id:
            return {
                "input_url": raw_url,
                "url": normalized_url,
                "status": "error",
                "error": "Failed to submit URL for analysis",
            }

        client.wait_for_analysis(analysis_id)
        time.sleep(config.inter_request_delay)
        report = client.get_url_report(normalized_url)

    if not report:
        return {
            "input_url": raw_url,
            "url": normalized_url,
            "status": "error",
            "error": "Failed to fetch final URL report",
        }

    attributes = report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats") or {}
    analysis_results = attributes.get("last_analysis_results") or {}

    normalized_stats = {
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
    }

    category, score_details = classify_threat_weighted(analysis_results, normalized_stats)
    top_detections = extract_top_detections(analysis_results, config.top_detections_limit)

    return {
        "input_url": raw_url,
        "url": normalized_url,
        "status": "ok",
        "stats": normalized_stats,
        "category": category,
        "score_details": score_details,
        "top_detections": top_detections,
    }


def save_json(results: List[Dict[str, object]], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logging.info("Saved JSON results to %s", output_path)


def save_csv(results: List[Dict[str, object]], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "input_url",
                "url",
                "status",
                "category",
                "malicious",
                "suspicious",
                "harmless",
                "undetected",
                "top_detections",
                "error",
            ]
        )
        for item in results:
            stats = item.get("stats", {}) if isinstance(item.get("stats"), dict) else {}
            detections = item.get("top_detections", [])
            detections_text = "; ".join(
                f"{d.get('vendor')}: {d.get('result')}" for d in detections if isinstance(d, dict)
            )
            writer.writerow(
                [
                    item.get("input_url", ""),
                    item.get("url", ""),
                    item.get("status", ""),
                    item.get("category", ""),
                    stats.get("malicious", 0),
                    stats.get("suspicious", 0),
                    stats.get("harmless", 0),
                    stats.get("undetected", 0),
                    detections_text,
                    item.get("error", ""),
                ]
            )
    logging.info("Saved CSV results to %s", output_path)


def generate_pdf(results: List[Dict[str, object]], output_path: str) -> None:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=16,
        spaceAfter=12,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.darkblue,
        spaceBefore=8,
        spaceAfter=6,
    )

    doc = SimpleDocTemplate(output_path, pagesize=A4, title="VirusTotal URL Scan Report")
    elements: List[object] = []

    elements.append(Paragraph("VirusTotal URL Scan Report", title_style))
    elements.append(
        Paragraph(
            safe_text(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}"),
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 12))

    if not results:
        elements.append(Paragraph("No results available.", styles["Normal"]))
        doc.build(elements)
        return

    for index, item in enumerate(results, start=1):
        elements.append(Paragraph(f"URL #{index}", section_style))
        elements.append(Paragraph(f"<b>Input URL:</b> {safe_text(item.get('input_url', ''))}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Normalized URL:</b> {safe_text(item.get('url', ''))}", styles["Normal"]))
        elements.append(Paragraph(f"<b>Status:</b> {safe_text(item.get('status', 'unknown'))}", styles["Normal"]))

        if item.get("status") != "ok":
            elements.append(Paragraph(f"<b>Error:</b> {safe_text(item.get('error', 'Unknown error'))}", styles["Normal"]))
            elements.append(Spacer(1, 12))
            continue

        stats = item.get("stats", {})
        stats_table = Table(
            [
                ["Metric", "Count"],
                ["Malicious", str(stats.get("malicious", 0))],
                ["Suspicious", str(stats.get("suspicious", 0))],
                ["Harmless", str(stats.get("harmless", 0))],
                ["Undetected", str(stats.get("undetected", 0))],
            ],
            colWidths=[130, 80],
        )
        stats_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ALIGN", (1, 1), (1, -1), "CENTER"),
                ]
            )
        )

        elements.append(Spacer(1, 6))
        elements.append(Paragraph(f"<b>Final Threat Category:</b> {safe_text(item.get('category', 'Unknown'))}", styles["Normal"]))
        elements.append(Spacer(1, 6))
        elements.append(stats_table)

        detections = item.get("top_detections", [])
        elements.append(Spacer(1, 8))
        elements.append(Paragraph("<b>Top Vendor Detections:</b>", styles["Normal"]))

        if detections:
            for detection in detections:
                vendor = safe_text(detection.get("vendor", "unknown"))
                result = safe_text(detection.get("result", ""))
                category = safe_text(detection.get("category", ""))
                elements.append(Paragraph(f"- {vendor}: {result} ({category})", styles["Normal"]))
        else:
            elements.append(Paragraph("No vendor detections for this URL.", styles["Normal"]))

        elements.append(Spacer(1, 14))

    doc.build(elements)
    logging.info("PDF report generated: %s", output_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VirusTotal URL scanner with PDF report")
    parser.add_argument("--api-key", default=os.getenv("VT_API_KEY", ""), help="VirusTotal API key")
    parser.add_argument("--urls-file", default="", help="Path to txt/csv file containing URLs")
    parser.add_argument(
        "--stdin-urls",
        action="store_true",
        help="Read URLs from terminal paste (end with Ctrl+Z then Enter on Windows)",
    )
    parser.add_argument("--pdf", default=DEFAULT_PDF_PATH, help="Output PDF path")
    parser.add_argument("--json", default="", help="Optional output JSON path")
    parser.add_argument("--csv", default="", help="Optional output CSV path")
    parser.add_argument(
        "--rate-limit-per-minute",
        type=int,
        default=4,
        help="API request pacing limit per minute (default: 4)",
    )
    parser.add_argument(
        "--lookups-per-minute",
        type=int,
        default=4,
        help="Used for ETA/progress display (default: 4 URL lookups per minute)",
    )
    parser.add_argument("--force-rescan", action="store_true", help="Always submit URL for a fresh analysis")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)

    api_key = (args.api_key or "").strip()
    if not api_key:
        logging.error("VirusTotal API key is required. Use --api-key or set VT_API_KEY.")
        return 1

    input_urls: List[str] = []
    if args.urls_file:
        try:
            input_urls = read_urls_from_file(args.urls_file)
        except Exception as exc:
            logging.error("Failed to read URLs from file: %s", exc)
            return 1
    elif args.stdin_urls:
        input_urls = read_urls_from_stdin()
    else:
        input_urls = read_urls_from_stdin()

    if not input_urls:
        logging.error("No URLs provided for scanning.")
        return 1

    # Remove exact duplicates while preserving order.
    seen = set()
    deduped_urls = []
    for item in input_urls:
        if item not in seen:
            deduped_urls.append(item)
            seen.add(item)

    config = VTConfig(
        api_key=api_key,
        force_rescan=args.force_rescan,
        rate_limit_per_minute=max(1, int(args.rate_limit_per_minute or 4)),
        lookups_per_minute=max(1, int(args.lookups_per_minute or 4)),
    )
    client = VirusTotalClient(config)

    total_urls = len(deduped_urls)
    estimated_seconds = (total_urls * 60.0) / float(config.lookups_per_minute)
    logging.info(
        "Rate limit pacing: %s requests/minute (minimum interval %.1fs per request)",
        config.rate_limit_per_minute,
        60.0 / float(config.rate_limit_per_minute),
    )
    logging.info(
        "ETA model: %s lookups/minute (1 lookup = 1 URL)",
        config.lookups_per_minute,
    )
    logging.info(
        "Estimated runtime: %s for %s URL(s), based on lookup rate",
        format_duration(estimated_seconds),
        total_urls,
    )

    results: List[Dict[str, object]] = []
    run_started = time.monotonic()
    for index, raw_url in enumerate(deduped_urls, start=1):
        logging.info("Processing URL %s/%s: %s", index, total_urls, raw_url)
        try:
            result = analyze_url(client, raw_url, config)
            results.append(result)
        except Exception as exc:
            logging.exception("Unexpected error while processing URL '%s': %s", raw_url, exc)
            results.append(
                {
                    "input_url": raw_url,
                    "url": raw_url,
                    "status": "error",
                    "error": f"Unexpected exception: {exc}",
                }
            )

        elapsed = time.monotonic() - run_started
        remaining_urls = total_urls - index
        estimated_remaining_seconds = (remaining_urls * 60.0) / float(config.lookups_per_minute)
        logging.info(
            "Progress %s/%s | requests made=%s | elapsed=%s | est remaining=%s",
            index,
            total_urls,
            client.request_count,
            format_duration(elapsed),
            format_duration(estimated_remaining_seconds),
        )

    json_path = args.json.strip() if args.json else ""
    csv_path = args.csv.strip() if args.csv else ""

    pdf_output_path = resolve_non_overwriting_path(args.pdf)
    if pdf_output_path != args.pdf:
        logging.info("PDF path exists, using next available name: %s", pdf_output_path)

    json_output_path = ""
    csv_output_path = ""
    if json_path:
        json_output_path = resolve_non_overwriting_path(json_path)
        if json_output_path != json_path:
            logging.info("JSON path exists, using next available name: %s", json_output_path)
    if csv_path:
        csv_output_path = resolve_non_overwriting_path(csv_path)
        if csv_output_path != csv_path:
            logging.info("CSV path exists, using next available name: %s", csv_output_path)

    if json_output_path:
        save_json(results, json_output_path)
    if csv_output_path:
        save_csv(results, csv_output_path)

    generate_pdf(results, pdf_output_path)

    logging.info("Scan completed: %s URLs processed", len(results))
    logging.info(
        "Total API requests made: %s in %s",
        client.request_count,
        format_duration(time.monotonic() - run_started),
    )
    if not json_path and not csv_path:
        logging.info(
            "Tip: use --json %s and/or --csv %s to export machine-readable results.",
            DEFAULT_JSON_PATH,
            DEFAULT_CSV_PATH,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())