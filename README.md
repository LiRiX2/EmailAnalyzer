# Email Analyzer

A Python tool for analyzing suspicious email messages (`.eml`). It parses headers, evaluates sender authenticity, extracts and scores URLs (including obfuscated links in HTML), analyzes attachments for executables and malicious Office macros, and produces a consolidated risk score — with full JSON export for case records.

Built around a SOC triage workflow: feed it a reported email, get back a structured verdict you can act on or attach to a ticket.

## Features

**Header & sender authenticity**
- Extracts core headers (From, To, Subject, Message-ID, X-Mailer) and the originating IP from the `Received` chain.
- **Visual vs. Truth Sender**: programmatically compares the From-header domain against the Return-Path domain to flag mismatches — independent of any authentication headers.
- **Authentication-Results with a trust boundary**: `SPF`/`DKIM`/`DMARC` results are only used for the spoofing verdict if the `Authentication-Results` header was added by a configured, trusted receiving MTA (`authserv-id`). This prevents an attacker-forged `Authentication-Results: ...; spf=pass; dkim=pass; dmarc=pass` header in the raw message from producing a false "clean" verdict.
- Geo-IP and basic blacklist status for the originating IP.
- Subject-line keyword detection (word-boundary matching to avoid false positives like "Win" in "showing").

**URL analysis**
- Extracts URLs from plain-text and HTML bodies, including `<a>`, `<img>`, `<script>`, `<iframe>`, `<link>`, and CSS `url()`.
- **Deceptive link detection**: flags links where the displayed text is itself a URL pointing to a different domain than the actual `href` — a common phishing pattern.
- Heuristic scoring: IP-as-domain, oversized query strings, credential/brand-related keywords in path or query.
- WHOIS lookups, including a "very young domain" check (domains registered within the last 30 days).
- Placeholders for VirusTotal and Safe Browsing API integration (no keys used in this public version).

**Attachment analysis**
- Extracts attachments to `attachments_extracted/` and computes MD5, SHA1, SHA256.
- Static analysis: flags executables, scripts, and Office documents.
- VBA macro analysis via `oletools`, including detection of auto-executing macros (`AutoOpen`, `Workbook_Open`, etc.).

**Risk assessment & export**
- Consolidated risk score and verdict (Low → Critical), combining all of the above.
- The risk assessment is part of the returned data structure — **it's included in the JSON export**, not just printed to console.
- Optional opsec mode: disable all external lookups (Geo-IP, WHOIS) so indicators are never sent to third parties during sensitive investigations.

## Getting Started

### Prerequisites

- Python 3.9+
- `pip`

### Installation

```bash
git clone https://github.com/LiRiX2/EmailAnalyzer.git
cd EmailAnalyzer
pip install -r requirements.txt
```

### Usage

```bash
python email_analyzer.py
```

The script prompts for the path to a `.eml` file (drag-and-drop the file into the terminal to insert its path), runs the analysis, prints a structured report, and offers to export the full results to JSON.

### Configuration

Both are environment variables, set before running the script.

| Variable | Default | Purpose |
|---|---|---|
| `EMAILANALYZER_TRUSTED_AUTHSERV_ID` | _(empty)_ | The `authserv-id` of your receiving MTA (e.g. `mx.example.com`). If unset, `Authentication-Results` is treated as untrusted and excluded from the spoofing verdict — only the Visual-vs-Truth domain comparison is used. |
| `EMAILANALYZER_EXTERNAL_LOOKUPS` | `1` | Set to `0` to disable Geo-IP and WHOIS lookups (opsec mode). |

Example:
```bash
EMAILANALYZER_TRUSTED_AUTHSERV_ID=mx.mycompany.com python email_analyzer.py
```

## Sample Output

```
--- Header Information ---
Visual Sender (From):                   "Microsoft 365" <no-reply@microsoft.com>
Truth Sender Domain (Return-Path):      m365-secure-login.com
Truth Sender (Originating IP):          203.0.113.45
------------------------------------------------------------
Auth authserv-id:                       attacker-forged.example
  SPF:                                  pass
  DKIM:                                 pass
  DMARC:                                pass
  Trust: Authentication-Results NOT trusted - set TRUSTED_AUTHSERV_ID to your
         boundary MTA. SPF/DKIM/DMARC values below are informational only and
         excluded from the spoofing verdict.
------------------------------------------------------------
!!! SPOOFING DETECTED !!!               YES
    - From domain (microsoft.com) != Return-Path domain (m365-secure-login.com)

--- HTML / Deceptive Link Findings ---
  - Deceptive link: text shows 'login.microsoftonline.com' but links to 'm365-secure-login.com'

Overall Risk Score: 8
Verdict: HIGH to CRITICAL Risk. Highly suspicious or malicious - extreme caution.
```

Note how the email passes SPF/DKIM/DMARC at face value — those values were forged in the raw message and originate from an untrusted `authserv-id`, so the tool correctly excludes them from the verdict and instead catches the spoofing via domain alignment and the deceptive link.

## Testing

To build test cases:
- Use "Show Original" / "Download Original" in your email client to get real `.eml` files.
- Craft HTML test emails with `<a>` tags where the link text is itself a URL pointing to a different domain.
- For attachment analysis: attach a renamed `dummy.exe`, and a `.docm`/`.xlsm` with a harmless test macro (`MsgBox` in `Sub AutoOpen()`).

## Future Enhancements

- VirusTotal and Safe Browsing API integration.
- Deeper HTML/JavaScript obfuscation analysis.
- Batch processing of multiple `.eml` files.
- Simple GUI.

## Author

Tobias Kastenhuber ([LiRiX2](https://github.com/LiRiX2))

## License

MIT License — see `LICENSE` for details.
