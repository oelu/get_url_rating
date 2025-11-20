# Get URL Rating

A Python script that extracts all URLs from a given webpage using requests and BeautifulSoup, with optional security scanning via VirusTotal and URLhaus.

## Features

- Fetches and parses any webpage
- Extracts all URLs from anchor tags (`<a>` elements)
- Automatically converts relative URLs to absolute URLs
- Built-in error handling for network and parsing issues
- URL validation
- Optional VirusTotal integration to check URLs for malicious content
- Optional URLhaus integration to check URLs against malware distribution database
- Support for using both security services simultaneously
- Rate limiting for VirusTotal API (respects free tier limits)

## Requirements

- Python 3.6+
- requests
- beautifulsoup4

## Installation

1. Clone or download this repository

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python get_url_rating.py <URL>
```

### Example

```bash
python get_url_rating.py https://example.com
```

Output:
```
Scraping URLs from: https://example.com

Found 3 URLs

https://example.com/page1
https://example.com/page2
https://www.iana.org/domains/example
```

### VirusTotal Integration

Check all found URLs against VirusTotal's database:

```bash
python get_url_rating.py https://example.com --virustotal --api-key YOUR_API_KEY
```

Or use an environment variable:

```bash
export VT_API_KEY=your_virustotal_api_key
python get_url_rating.py https://example.com --virustotal
```

#### VirusTotal Options

- `-vt, --virustotal` - Enable VirusTotal checking
- `--api-key API_KEY` - VirusTotal API key (or use `VT_API_KEY` environment variable)
- `--delay SECONDS` - Delay between API calls (default: 15 seconds for free tier)

#### Example Output with VirusTotal

```
Scraping URLs from: https://example.com

Found 3 URLs

Checking URLs against VirusTotal (delay: 15s between requests)...

[CLEAN] https://example.com/page1
  Malicious: 0/85, Suspicious: 0/85, Harmless: 75/85, Undetected: 10/85

[SUSPICIOUS] https://example.com/page2
  Malicious: 0/85, Suspicious: 2/85, Harmless: 70/85, Undetected: 13/85

[SUBMITTED] https://example.com/page3
  URL submitted for scanning. Check later for results.
```

### Getting a VirusTotal API Key

1. Sign up for a free account at [VirusTotal](https://www.virustotal.com/)
2. Go to your profile settings
3. Copy your API key
4. Note: Free tier is limited to 4 requests per minute

### URLhaus Integration

Check all found URLs against URLhaus's malware distribution database:

```bash
python get_url_rating.py https://example.com --urlhaus --urlhaus-key YOUR_AUTH_KEY
```

Or use an environment variable:

```bash
export URLHAUS_API_KEY=your_urlhaus_auth_key
python get_url_rating.py https://example.com --urlhaus
```

#### URLhaus Options

- `-uh, --urlhaus` - Enable URLhaus checking
- `--urlhaus-key AUTH_KEY` - URLhaus Auth-Key (or use `URLHAUS_API_KEY` environment variable)

#### Example Output with URLhaus

```
Scraping URLs from: https://example.com

Found 3 URLs

Checking URLs against URLhaus...

URLhaus:
[CLEAN] https://example.com/page1
  URL not found in URLhaus database

URLhaus:
[MALICIOUS - ONLINE] https://malicious-site.example/malware.exe
  Threat: malware_download
  Tags: exe, trojan, AsyncRAT
  Date Added: 2024-01-15 10:30:00
  Reference: https://urlhaus.abuse.ch/url/12345/

URLhaus:
[MALICIOUS - OFFLINE] https://old-malware.example/payload.zip
  Threat: malware_download
  Tags: zip, emotet
  Date Added: 2024-01-10 08:15:00
  Reference: https://urlhaus.abuse.ch/url/12346/
```

#### Getting a URLhaus Auth-Key

1. Visit [abuse.ch authentication portal](https://auth.abuse.ch/)
2. Register for a free account
3. Get your Auth-Key from your account dashboard
4. Note: Auth-Key is required for API access

### Using Both Services Together

You can check URLs against both VirusTotal and URLhaus simultaneously:

```bash
python get_url_rating.py https://example.com \
  --virustotal --api-key YOUR_VT_KEY \
  --urlhaus --urlhaus-key YOUR_UH_KEY
```

Or with environment variables:

```bash
export VT_API_KEY=your_virustotal_api_key
export URLHAUS_API_KEY=your_urlhaus_auth_key
python get_url_rating.py https://example.com --virustotal --urlhaus
```

This will check each URL against both services and display results from both.

## How It Works

### Basic Scraping

1. Takes a URL as a command-line argument
2. Sends an HTTP GET request to fetch the webpage
3. Parses the HTML content using BeautifulSoup
4. Finds all `<a>` tags with `href` attributes
5. Converts relative URLs to absolute URLs
6. Prints the complete list of URLs found

### VirusTotal Checking (Optional)

When enabled with `--virustotal`:
1. For each found URL, encodes it in base64 format
2. Queries the VirusTotal API v3 for existing scan results
3. If URL hasn't been scanned, submits it for analysis
4. Displays security status based on detection results:
   - `[CLEAN]` - No detections
   - `[SUSPICIOUS]` - Some suspicious detections
   - `[MALICIOUS]` - Flagged as malicious
   - `[SUBMITTED]` - New submission, check later
5. Respects API rate limits with configurable delays

### URLhaus Checking (Optional)

When enabled with `--urlhaus`:
1. For each found URL, queries the URLhaus API v1
2. Checks if the URL exists in URLhaus's malware distribution database
3. Displays security status based on URLhaus results:
   - `[CLEAN]` - URL not found in URLhaus database
   - `[MALICIOUS - ONLINE]` - Active malware distribution site
   - `[MALICIOUS - OFFLINE]` - Known malware site (currently offline)
4. Shows additional context:
   - Threat type (malware_download, phishing, etc.)
   - Tags (malware families, file types)
   - Date the URL was added to the database
   - Reference link to URLhaus report
5. Requires free Auth-Key from abuse.ch

## Testing

The project includes unit tests for the display functions. Tests are written without mocking and only test functions that don't require external API calls.

### Running Tests

With pytest:
```bash
python3 -m pytest test_get_url_rating.py -v
```

With unittest:
```bash
python3 test_get_url_rating.py -v
```

### Test Coverage

The tests cover:
- `display_virustotal_result()` - Testing all result types (clean, malicious, suspicious, submitted, error)
- `display_urlhaus_result()` - Testing all result types (clean, malicious online/offline, error, edge cases)

## Error Handling

The script handles:
- Invalid URLs (missing scheme or domain)
- Network errors (connection issues, timeouts)
- HTTP errors (404, 500, etc.)
- HTML parsing errors
- VirusTotal API errors and rate limiting
- URLhaus API errors and authentication issues
- Missing API keys (with helpful warnings and instructions)
