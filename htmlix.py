#!/usr/bin/env python3
"""
HTML Injection Scanner
======================

Tests URL query parameters for reflected HTML injection by substituting
payloads (loaded from a file) into each parameter and checking whether the
payload is reflected UN-escaped in the response body.

INTENDED USE
------------
Only run this against applications you own or are explicitly authorized to
test. Unauthorized scanning is illegal in most jurisdictions.

USAGE
-----
    # Single URL, payloads from file
    python html_injection_scanner.py -u "https://example.com/search?q=test" -p payloads.txt

    # Many URLs from a file (one per line), POST method, more threads
    python html_injection_scanner.py -U urls.txt -p payloads.txt -m POST -t 20

    # Save results to JSON
    python html_injection_scanner.py -u "https://example.com/?name=x" -p payloads.txt -o results.json

PAYLOAD FILE FORMAT
-------------------
One payload per line. Blank lines and lines starting with '#' are ignored.
Example:
    <b>hi</b>
    <img src=x onerror=alert(1)>
    "><h1>injected</h1>
"""

import argparse
import concurrent.futures
import html
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("This tool needs 'requests'. Install with:  pip install requests")


# ----------------------------------------------------------------------------
# Data model
# ----------------------------------------------------------------------------
@dataclass
class Finding:
    url: str
    parameter: str
    payload: str
    method: str
    reflected_raw: bool          # payload appears verbatim (unescaped)
    reflected_escaped: bool      # payload appears only HTML-escaped
    status_code: Optional[int]
    error: Optional[str] = None

    @property
    def vulnerable(self) -> bool:
        return self.reflected_raw


@dataclass
class ScanConfig:
    payloads: list = field(default_factory=list)
    method: str = "GET"
    threads: int = 10
    timeout: float = 10.0
    verify_tls: bool = True
    headers: dict = field(default_factory=dict)
    delay: float = 0.0           # per-request politeness delay (seconds)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def load_lines(path: str) -> list:
    """Load non-empty, non-comment lines from a file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [
                line.rstrip("\n")
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except OSError as exc:
        sys.exit(f"Could not read '{path}': {exc}")


def build_session(config: ScanConfig) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "HEAD"]),
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=config.threads,
                          pool_maxsize=config.threads)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    default_headers = {
        "User-Agent": "html-injection-scanner/1.0 (authorized-testing)",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }
    default_headers.update(config.headers)
    session.headers.update(default_headers)
    return session


def unique_marker(payload: str) -> str:
    """
    Wrap the payload with a random-ish marker so we can find reflections
    reliably even when the app already contains similar text.
    Returns (wrapped_payload, marker).
    """
    marker = f"hijx{abs(hash(payload)) % 1_000_000}"
    return f"{marker}{payload}{marker}", marker


# ----------------------------------------------------------------------------
# Core scanning logic
# ----------------------------------------------------------------------------
def scan_parameter(session: requests.Session, config: ScanConfig,
                   url: str, param: str, base_params: dict,
                   payload: str) -> Finding:
    """Send one request with `payload` injected into `param`, then analyze."""
    wrapped, marker = unique_marker(payload)

    # Copy params and overwrite the target parameter with the wrapped payload.
    test_params = {k: v[:] if isinstance(v, list) else v
                   for k, v in base_params.items()}
    test_params[param] = wrapped

    parsed = urlparse(url)

    try:
        if config.delay:
            time.sleep(config.delay)

        if config.method.upper() == "POST":
            target = urlunparse(parsed._replace(query=""))
            resp = session.post(target, data=test_params,
                                timeout=config.timeout,
                                verify=config.verify_tls,
                                allow_redirects=True)
        else:
            query = urlencode(test_params, doseq=True)
            target = urlunparse(parsed._replace(query=query))
            resp = session.get(target, timeout=config.timeout,
                               verify=config.verify_tls,
                               allow_redirects=True)

        body = resp.text or ""
        raw_needle = f"{marker}{payload}{marker}"
        escaped_needle = html.escape(f"{marker}{payload}{marker}", quote=True)

        reflected_raw = raw_needle in body
        reflected_escaped = (not reflected_raw) and (escaped_needle in body)

        return Finding(
            url=url, parameter=param, payload=payload,
            method=config.method.upper(),
            reflected_raw=reflected_raw,
            reflected_escaped=reflected_escaped,
            status_code=resp.status_code,
        )

    except requests.RequestException as exc:
        return Finding(
            url=url, parameter=param, payload=payload,
            method=config.method.upper(),
            reflected_raw=False, reflected_escaped=False,
            status_code=None, error=str(exc),
        )


def scan_url(session: requests.Session, config: ScanConfig, url: str,
             executor: concurrent.futures.ThreadPoolExecutor) -> list:
    """Enumerate parameters of a URL and test every payload against each."""
    parsed = urlparse(url)
    base_params = parse_qs(parsed.query, keep_blank_values=True)

    if not base_params:
        print(f"[!] No query parameters found in: {url}  (skipping)",
              file=sys.stderr)
        return []

    print(f"[*] Scanning {url}  "
          f"params={list(base_params)}  payloads={len(config.payloads)}")

    futures = []
    for param in base_params:
        for payload in config.payloads:
            futures.append(
                executor.submit(scan_parameter, session, config,
                                url, param, base_params, payload)
            )

    findings = []
    for fut in concurrent.futures.as_completed(futures):
        finding = fut.result()
        findings.append(finding)
        if finding.vulnerable:
            print(f"    [VULNERABLE] param='{finding.parameter}' "
                  f"payload={finding.payload!r} -> reflected unescaped "
                  f"(HTTP {finding.status_code})")
    return findings


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------
def print_summary(findings: list) -> None:
    vulns = [f for f in findings if f.vulnerable]
    escaped = [f for f in findings if f.reflected_escaped]
    errors = [f for f in findings if f.error]

    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Requests analyzed : {len(findings)}")
    print(f"Vulnerable hits   : {len(vulns)}")
    print(f"Escaped (safe)    : {len(escaped)}")
    print(f"Errors            : {len(errors)}")

    if vulns:
        print("\nConfirmed HTML injection points:")
        seen = set()
        for f in vulns:
            key = (f.url, f.parameter)
            if key in seen:
                continue
            seen.add(key)
            print(f"  - {f.method} {f.url}  [param: {f.parameter}]")
    print("=" * 60)


def save_json(findings: list, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2)
    print(f"[*] Results written to {path}")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Reflected HTML injection scanner (authorized use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-u", "--url", help="Single target URL (with parameters)")
    src.add_argument("-U", "--url-file", help="File of target URLs, one per line")

    p.add_argument("-p", "--payloads", required=True,
                   help="File containing payloads, one per line")
    p.add_argument("-m", "--method", default="GET", choices=["GET", "POST"],
                   help="HTTP method (default: GET)")
    p.add_argument("-t", "--threads", type=int, default=10,
                   help="Concurrent requests (default: 10)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Delay between requests per worker, seconds (default: 0)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Extra header 'Name: Value' (repeatable)")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="Disable TLS certificate verification")
    p.add_argument("-o", "--output", help="Write full results to JSON file")
    return p.parse_args()


def parse_headers(raw_headers: list) -> dict:
    headers = {}
    for item in raw_headers:
        if ":" not in item:
            sys.exit(f"Bad header (need 'Name: Value'): {item}")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    return headers


def main() -> None:
    args = parse_args()

    payloads = load_lines(args.payloads)
    if not payloads:
        sys.exit("Payload file is empty.")

    if args.url:
        urls = [args.url]
    else:
        urls = load_lines(args.url_file)
    if not urls:
        sys.exit("No target URLs to scan.")

    config = ScanConfig(
        payloads=payloads,
        method=args.method,
        threads=max(1, args.threads),
        timeout=args.timeout,
        verify_tls=not args.insecure,
        headers=parse_headers(args.header),
        delay=max(0.0, args.delay),
    )

    session = build_session(config)
    all_findings = []

    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as ex:
        for url in urls:
            all_findings.extend(scan_url(session, config, url, ex))

    print_summary(all_findings)
    print(f"[*] Done in {time.time() - started:.1f}s")

    if args.output:
        save_json(all_findings, args.output)

    # Non-zero exit if anything vulnerable — handy for CI pipelines.
    sys.exit(1 if any(f.vulnerable for f in all_findings) else 0)


if __name__ == "__main__":
    main()
