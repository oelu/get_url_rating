#!/usr/bin/env python3
"""
URL Scraper - Extracts all URLs from a given webpage
"""

import sys
import os
import argparse
import time
import base64
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def scrape_urls(url):
    """
    Fetch a webpage and extract all URLs found in it.

    Args:
        url: The URL to scrape

    Returns:
        A list of URLs found in the webpage
    """
    try:
        # Send GET request to the URL
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all anchor tags with href attributes
        urls = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            # Convert relative URLs to absolute URLs
            absolute_url = urljoin(url, href)
            urls.append(absolute_url)

        return urls

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing webpage: {e}", file=sys.stderr)
        sys.exit(1)


def check_url_with_virustotal(url, api_key):
    """
    Check a URL against VirusTotal API.

    Args:
        url: The URL to check
        api_key: VirusTotal API key

    Returns:
        A dictionary with VirusTotal scan results or None if error
    """
    # Encode URL for VirusTotal API (base64 without padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    headers = {
        "x-apikey": api_key
    }

    try:
        # Get URL analysis
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:
            # URL not found, submit it for scanning
            submit_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10
            )

            if submit_response.status_code == 200:
                return {
                    "status": "submitted",
                    "message": "URL submitted for scanning. Check later for results."
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to submit URL: {submit_response.status_code}"
                }

        elif response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()) if stats else 0
            }

        else:
            return {
                "status": "error",
                "message": f"API error: {response.status_code}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"Request failed: {str(e)}"
        }


def display_virustotal_result(url, result):
    """Display VirusTotal scan results in a readable format."""
    if result["status"] == "success":
        malicious = result["malicious"]
        suspicious = result["suspicious"]
        total = result["total"]

        if malicious > 0:
            status_indicator = "[MALICIOUS]"
        elif suspicious > 0:
            status_indicator = "[SUSPICIOUS]"
        else:
            status_indicator = "[CLEAN]"

        print(f"{status_indicator} {url}")
        print(f"  Malicious: {malicious}/{total}, Suspicious: {suspicious}/{total}, "
              f"Harmless: {result['harmless']}/{total}, Undetected: {result['undetected']}/{total}")

    elif result["status"] == "submitted":
        print(f"[SUBMITTED] {url}")
        print(f"  {result['message']}")

    else:
        print(f"[ERROR] {url}")
        print(f"  {result['message']}")


def check_url_with_urlhaus(url, auth_key=None):
    """
    Check a URL against URLhaus API.

    Args:
        url: The URL to check
        auth_key: Optional URLhaus auth key from https://auth.abuse.ch/

    Returns:
        A dictionary with URLhaus scan results or None if error
    """
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
    }

    if auth_key:
        headers["Auth-Key"] = auth_key

    try:
        response = requests.post(
            api_url,
            data={"url": url},
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            query_status = data.get("query_status")

            if query_status == "ok":
                return {
                    "status": "found",
                    "url_status": data.get("url_status", "unknown"),
                    "threat": data.get("threat", "unknown"),
                    "tags": data.get("tags", []),
                    "date_added": data.get("date_added"),
                    "urlhaus_reference": data.get("urlhaus_reference", "")
                }
            elif query_status == "no_results":
                return {
                    "status": "not_found",
                    "message": "URL not found in URLhaus database"
                }
            else:
                return {
                    "status": "error",
                    "message": f"Unknown query status: {query_status}"
                }
        else:
            # Try to get more details from the response
            try:
                error_data = response.json()
                error_msg = error_data.get("message", f"API error: {response.status_code}")
            except:
                error_msg = f"API error: {response.status_code}"

            return {
                "status": "error",
                "message": error_msg
            }

    except requests.exceptions.RequestException as e:
        return {
            "status": "error",
            "message": f"Request failed: {str(e)}"
        }


def display_urlhaus_result(url, result):
    """Display URLhaus scan results in a readable format."""
    if result["status"] == "found":
        url_status = result["url_status"]
        threat = result["threat"]

        if url_status == "online":
            status_indicator = "[MALICIOUS - ONLINE]"
        elif url_status == "offline":
            status_indicator = "[MALICIOUS - OFFLINE]"
        else:
            status_indicator = f"[MALICIOUS - {url_status.upper()}]"

        print(f"{status_indicator} {url}")
        print(f"  Threat: {threat}")
        if result["tags"]:
            print(f"  Tags: {', '.join(result['tags'])}")
        if result["date_added"]:
            print(f"  Date Added: {result['date_added']}")
        if result["urlhaus_reference"]:
            print(f"  Reference: {result['urlhaus_reference']}")

    elif result["status"] == "not_found":
        print(f"[CLEAN] {url}")
        print(f"  {result['message']}")

    else:
        print(f"[ERROR] {url}")
        print(f"  {result['message']}")


def main():
    parser = argparse.ArgumentParser(
        description="Extract URLs from a webpage and optionally check them against security services"
    )
    parser.add_argument("url", help="The URL to scrape")
    parser.add_argument(
        "-vt", "--virustotal",
        action="store_true",
        help="Check URLs against VirusTotal API"
    )
    parser.add_argument(
        "--api-key",
        help="VirusTotal API key (or set VT_API_KEY environment variable)"
    )
    parser.add_argument(
        "-uh", "--urlhaus",
        action="store_true",
        help="Check URLs against URLhaus API"
    )
    parser.add_argument(
        "--urlhaus-key",
        help="URLhaus Auth-Key from https://auth.abuse.ch/ (or set URLHAUS_API_KEY environment variable)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=15,
        help="Delay in seconds between API calls (default: 15, for VirusTotal free tier limit of 4 requests/min)"
    )

    args = parser.parse_args()

    # Basic URL validation
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        print("Error: Invalid URL. Please provide a valid URL with scheme (http:// or https://)", file=sys.stderr)
        sys.exit(1)

    # Handle VirusTotal API key
    if args.virustotal:
        api_key = args.api_key or os.getenv("VT_API_KEY")
        if not api_key:
            print("Error: VirusTotal API key required. Use --api-key or set VT_API_KEY environment variable.",
                  file=sys.stderr)
            sys.exit(1)

    # Handle URLhaus Auth-Key
    urlhaus_key = None
    if args.urlhaus:
        urlhaus_key = args.urlhaus_key or os.getenv("URLHAUS_API_KEY")
        if not urlhaus_key:
            print("Warning: URLhaus Auth-Key not provided. Requests may be limited or blocked.",
                  file=sys.stderr)
            print("Get a free key at https://auth.abuse.ch/ and use --urlhaus-key or set URLHAUS_API_KEY environment variable.",
                  file=sys.stderr)
            print()

    print(f"Scraping URLs from: {args.url}\n")

    urls = scrape_urls(args.url)

    if urls:
        print(f"Found {len(urls)} URLs")

        # Check if any security service was requested
        if args.virustotal or args.urlhaus:
            services = []
            if args.virustotal:
                services.append("VirusTotal")
            if args.urlhaus:
                services.append("URLhaus")

            print(f"\nChecking URLs against {' and '.join(services)}...\n")

            for i, found_url in enumerate(urls):
                # Check with VirusTotal
                if args.virustotal:
                    print("VirusTotal:")
                    result = check_url_with_virustotal(found_url, api_key)
                    display_virustotal_result(found_url, result)
                    print()

                # Check with URLhaus
                if args.urlhaus:
                    print("URLhaus:")
                    result = check_url_with_urlhaus(found_url, urlhaus_key)
                    display_urlhaus_result(found_url, result)
                    print()

                # Rate limiting (mainly for VirusTotal free tier)
                if args.virustotal and i < len(urls) - 1:
                    print(f"Waiting {args.delay}s before next request...\n")
                    time.sleep(args.delay)
        else:
            print()
            for found_url in urls:
                print(found_url)
    else:
        print("No URLs found on the webpage.")


if __name__ == "__main__":
    main()
