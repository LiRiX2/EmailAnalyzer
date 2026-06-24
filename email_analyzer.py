import email
from email import policy
from email.parser import BytesParser
import re
import requests
import whois  # pip install python-whois
from urllib.parse import urlparse
import hashlib
import os
from datetime import datetime, timedelta, timezone
import dateutil.parser  # pip install python-dateutil
import traceback
import logging

from oletools.olevba import VBA_Parser  # pip install oletools - macro analysis
from bs4 import BeautifulSoup  # pip install beautifulsoup4
import json

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger("email_analyzer")

# --- Config ---

ATTACHMENT_SAVE_DIR = "attachments_extracted"

# external lookups (geo-ip, whois) leak IOCs to third parties - opt-out via env
ENABLE_EXTERNAL_LOOKUPS = os.environ.get("EMAILANALYZER_EXTERNAL_LOOKUPS", "1") != "0"

# only the A-R header from our own receiving MTA is trustworthy; attacker can forge
# the rest. set this to your boundary MTA's authserv-id, else A-R is ignored for the verdict.
TRUSTED_AUTHSERV_ID = os.environ.get("EMAILANALYZER_TRUSTED_AUTHSERV_ID", "")


# --- IP / keyword helpers ---

def get_geo_ip_info(ip_address):
    if not ENABLE_EXTERNAL_LOOKUPS:
        return None
    if not ip_address or ip_address == "No IP found in Received Header":
        return None

    # free ip-api endpoint is http-only; use GeoLite2 or a paid HTTPS API in prod
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        if data and data.get('status') == 'success':
            return {
                'country': data.get('country'),
                'city': data.get('city'),
                'isp': data.get('isp')
            }
        else:
            logger.warning("Geo-IP-API error for %s: %s", ip_address, data.get('message', 'Unknown error'))
            return None
    except requests.exceptions.RequestException as e:
        logger.warning("Error during Geo-IP query for %s: %s", ip_address, e)
        return None


def check_ip_blacklist(ip_address):
    # stub - swap for a real RBL / threat-intel lookup
    if not ip_address or ip_address == "No IP found in Received Header":
        return "N/A"

    if ip_address == "192.0.2.1":
        return "Known Test IP (Highly Suspicious)"
    elif ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172.16."):
        return "Private IP (Internal Network, Not Publicly Routable)"
    elif ip_address.startswith("1.2.3."):
        return "Suspicious Subnet (Demo Example)"
    else:
        return "Clean (No specific blacklist hit in demo / Public IP)"


def search_keywords_in_subject(subject, keywords):
    # word boundaries so "Win" doesn't match inside "showing"
    if not subject:
        return []

    found_keywords = []
    subject_lower = subject.lower()
    for keyword in keywords:
        if re.search(r'\b' + re.escape(keyword.lower()) + r'\b', subject_lower):
            found_keywords.append(keyword)
    return found_keywords


# --- URL analysis ---

def extract_urls_from_text(text):
    if not text:
        return []
    # grab everything from the scheme up to the next whitespace/closing char
    url_pattern = re.compile(
        r'(?:https?|ftp|file)://'
        r'[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    # strip trailing punctuation that gets caught
    return [u.rstrip('.,);\'"') for u in url_pattern.findall(text)]


def get_whois_info(domain):
    if not ENABLE_EXTERNAL_LOOKUPS:
        return None
    try:
        w = whois.whois(domain)
        if w:
            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'updated_date': w.updated_date,
                'emails': w.emails
            }
        return None
    except Exception as e:
        logger.debug("WHOIS query failed for %s: %s", domain, e)
        return None


def analyze_url_for_suspicious_patterns(url):
    suspicious_patterns = []
    url_score = 0

    parsed_url = urlparse(url)
    host = parsed_url.hostname or ""  # hostname strips port/userinfo, unlike netloc
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    # raw IP instead of a domain (v4 or v6 literal)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) or \
            re.match(r'^[0-9a-fA-F:]+$', host) and ':' in host:
        suspicious_patterns.append("IP as domain")
        url_score += 3

    # very long query string - common obfuscation
    if len(query) > 100:
        suspicious_patterns.append(f"Long query ({len(query)} chars)")
        url_score += 2

    # brand / action keywords in path or query
    suspicious_url_keywords = ["login", "update", "verify", "admin", "account", "security", "alert",
                               "bank", "paypal", "invoice", "payment", "support", "amazon", "apple",
                               "microsoft", "icloud", "dropbox", "onedrive"]
    for keyword in suspicious_url_keywords:
        if keyword in path.lower() or keyword in query.lower():
            if keyword not in suspicious_patterns:
                suspicious_patterns.append(keyword)
                url_score += 1

    return suspicious_patterns, url_score


def get_heuristic_url_verdict(url_entry):
    # verdict from score + whois domain age, no external reputation APIs
    score = url_entry.get('url_score', 0)
    whois_info = url_entry.get('whois_info')

    if "IP as domain" in url_entry.get('suspicious_patterns', []):
        return "Malicious (IP as domain - Heuristic)"

    if score >= 3:
        return "Malicious (High Score - Heuristic)"
    elif score >= 1:
        return "Suspicious (Medium Score - Heuristic)"

    if isinstance(whois_info, dict):
        creation_date = whois_info.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        if creation_date:
            try:
                parsed_creation_date = dateutil.parser.parse(str(creation_date))
                # normalize both sides to tz-aware UTC, else naive/aware subtraction throws
                if parsed_creation_date.tzinfo is None:
                    parsed_creation_date = parsed_creation_date.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if now - parsed_creation_date < timedelta(days=30):
                    return "Highly Suspicious (Very Young Domain - Heuristic)"
            except (ValueError, OverflowError, TypeError) as e:
                logger.debug("Could not parse WHOIS creation date '%s': %s", creation_date, e)

    if score == 0:
        return "Potentially Clean (Heuristic)"

    return "Unknown (Heuristic)"


def check_url_google_safe_browsing(url, api_key=None):
    # stub - GSB threatMatches:find would go here if a key is configured
    if api_key:
        return "SKIPPED (Google Safe Browsing - API key available but not implemented)"
    else:
        return "SKIPPED (Google Safe Browsing - API key not provided)"


def export_results_to_json(data, output_filename):
    try:
        # datetime isn't JSON-serializable - walk the structure and convert to ISO strings
        def convert_datetime_to_str(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, list):
                return [convert_datetime_to_str(elem) for elem in obj]
            if isinstance(obj, dict):
                return {key: convert_datetime_to_str(value) for key, value in obj.items()}
            return obj

        serializable_data = convert_datetime_to_str(data)

        with open(output_filename, 'w', encoding='utf-8') as f:
            json.dump(serializable_data, f, indent=4, ensure_ascii=False)
        print(f"\nResults successfully exported to '{output_filename}'")
    except Exception as e:
        logger.error("Error exporting results to JSON: %s", e)
        traceback.print_exc()


# --- Attachment analysis ---

def calculate_file_hashes(file_path):
    hashes = {'md5': '', 'sha1': '', 'sha256': ''}
    try:
        with open(file_path, 'rb') as f:
            bytes_content = f.read()
            hashes['md5'] = hashlib.md5(bytes_content).hexdigest()
            hashes['sha1'] = hashlib.sha1(bytes_content).hexdigest()
            hashes['sha256'] = hashlib.sha256(bytes_content).hexdigest()
    except FileNotFoundError:
        logger.error("File '%s' not found for hash calculation.", file_path)
    except Exception as e:
        logger.error("Error calculating hash for %s: %s", file_path, e)
    return hashes


def analyze_attachment_static(file_path):
    # extension triage + VBA macro check for Office docs
    analysis_results = []
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1].lower()

    if file_extension in ('.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1'):
        analysis_results.append("Executable file detected. HIGHLY SUSPICIOUS!")
    elif file_extension in ('.js', '.vbs', '.hta'):
        analysis_results.append("Script file detected. Potentially suspicious.")

    if file_extension in ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.docm', '.xlsm', '.pptm'):
        vba_parser = None
        try:
            vba_parser = VBA_Parser(file_path)
            if vba_parser.detect_vba_macros():
                analysis_results.append("Macro-enabled Office document detected. HIGHLY SUSPICIOUS!")

                # auto-exec keywords = runs on open/close without user action
                auto_exec_macros = []
                for (filename_in_doc, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    if vba_code and re.search(
                            r'autoopen|autoclose|workbook_open|document_open|document_close|autoexec',
                            vba_code, re.IGNORECASE):
                        auto_exec_macros.append(vba_filename)

                if auto_exec_macros:
                    analysis_results.append(f"Auto-executing macros found in: {', '.join(auto_exec_macros)}")
            else:
                analysis_results.append("Office document found, no VBA macros detected.")
        except Exception as e:
            analysis_results.append(f"Could not analyze Office document with oletools: {e}")
            logger.debug("oletools error for %s: %s", file_path, e)
        finally:
            if vba_parser is not None:
                try:
                    vba_parser.close()
                except Exception:
                    pass

    if not analysis_results:
        analysis_results.append("No specific static analysis findings.")

    return analysis_results


# --- Header helper ---

def _extract_domain(value):
    if not value:
        return None
    m = re.search(r'@([a-zA-Z0-9.-]+)', value)
    return m.group(1).lower().rstrip('.>') if m else None


# --- Risk scoring (central, so the score also ends up in the JSON export) ---

def compute_overall_risk(parsed_data):
    alerts = []
    risk_score = 0
    headers = parsed_data.get('Headers', {})

    if headers.get('Spoofing_Detected'):
        reasons = "; ".join(headers.get('Spoofing_Reasons', [])) or "authentication/alignment failure"
        alerts.append(f"Potential spoofing detected ({reasons}) (High Risk)")
        risk_score += 3

    blacklist = headers.get('Origin_IP_Blacklist_Status')
    if blacklist not in ["Clean (No specific blacklist hit in demo / Public IP)", "N/A",
                         "Private IP (Internal Network, Not Publicly Routable)"]:
        alerts.append("Origin IP is blacklisted or suspicious (Medium Risk)")
        risk_score += 2

    subj_kw = headers.get('Suspicious_Subject_Keywords')
    if subj_kw and subj_kw != "No suspicious keywords found":
        alerts.append(f"Suspicious keywords in subject: {subj_kw} (Low-Medium Risk)")
        risk_score += 1

    # deceptive link = displayed domain != actual href domain
    for finding in parsed_data.get('HTML_Findings', []):
        alerts.append(f"{finding} (High Risk)")
        risk_score += 3

    # dampen URL contribution: lots of low-score URLs shouldn't dominate the total
    url_total = 0
    if isinstance(parsed_data.get('URLs'), list):
        for url_entry in parsed_data['URLs']:
            if url_entry.get('url_score', 0) > 0:
                url_total += url_entry['url_score']
    if url_total > 0:
        risk_score += (url_total // 2) + 1

    # attachments are weighted highest - executables and auto-macros are the worst case
    for att_entry in parsed_data.get('Attachments', []):
        if att_entry.get('error'):
            alerts.append(f"Error processing attachment '{att_entry.get('filename', 'N/A')}' (Medium Risk)")
            risk_score += 2
        for finding in att_entry.get('static_analysis', []):
            if "Executable file detected" in finding:
                alerts.append(f"Attachment '{att_entry.get('filename')}' is executable (CRITICAL)")
                risk_score += 5
            elif "Auto-executing macros found" in finding:
                alerts.append(f"Attachment '{att_entry.get('filename')}' has auto-executing macros (EXTREME)")
                risk_score += 4
            elif "Macro-enabled Office document detected" in finding:
                alerts.append(f"Attachment '{att_entry.get('filename')}' is macro-enabled (High Risk)")
                risk_score += 3
            elif "Potentially suspicious" in finding or "Script file detected" in finding:
                alerts.append(f"Attachment '{att_entry.get('filename')}' has suspicious static findings (Medium)")
                risk_score += 2

    if risk_score == 0:
        verdict = "No obvious risks found (based on current analysis)."
    elif risk_score <= 3:
        verdict = "Low to Medium Risk. Review carefully."
    elif risk_score <= 7:
        verdict = "Medium to High Risk. Several suspicious indicators - proceed with caution."
    else:
        verdict = "HIGH to CRITICAL Risk. Highly suspicious or malicious - extreme caution."

    return {'score': risk_score, 'verdict': verdict, 'alerts': alerts}


# --- Main parse + analyze ---

def parse_email(file_path):
    email_body = ""
    extracted_urls_from_html = []
    html_findings = []

    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        analysis_results = {
            'Headers': {},
            'URLs': [],
            'Attachments': [],
            'HTML_Findings': [],
            'Body_Content': ""
        }

        # --- Headers ---
        analysis_results['Headers'] = {
            'From': msg.get('From'),
            'To': msg.get('To'),
            'Subject': msg.get('Subject'),
            'Message-ID': msg.get('Message-ID'),
            'X-Mailer': msg.get('X-Mailer')
        }

        # origin IP: walk Received headers bottom-up (oldest hop = closest to sender)
        received_headers = msg.get_all('Received')
        origin_ip = "No IP found in Received Header"
        if received_headers:
            for received_header in reversed(received_headers):
                ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_header)
                if ip_match:
                    origin_ip = ip_match.group(1)
                    break
            # fallback: IP right after from/by when not in brackets
            if origin_ip == "No IP found in Received Header":
                for received_header in reversed(received_headers):
                    ip_match_direct = re.search(r'(?:from|by)\s+\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                                                received_header)
                    if ip_match_direct:
                        origin_ip = ip_match_direct.group(1)
                        break
        analysis_results['Headers']['Origin_IP'] = origin_ip

        # From domain vs Return-Path domain (alignment check feeds the spoofing verdict)
        from_domain = _extract_domain(analysis_results['Headers']['From'])
        analysis_results['Headers']['Sender_Domain'] = from_domain or "Not available"

        return_path = msg.get('Return-Path')
        rp_domain = _extract_domain(return_path)
        analysis_results['Headers']['Return_Path_Domain'] = rp_domain or (return_path or "Not found")

        # --- Authentication-Results (with trust boundary) ---
        # take the topmost A-R header (last one prepended = added by our receiving infra)
        auth_results_all = msg.get_all('Authentication-Results') or []
        spf_result = dkim_result = dmarc_result = "Not available"
        authserv_id = ""
        ar_trusted = False

        if auth_results_all:
            auth_results = str(auth_results_all[0])
            authserv_id = auth_results.split(';', 1)[0].strip().split()[0] if auth_results else ""

            def _grab(field):
                m = re.search(field + r'=(\w+)', auth_results)
                return m.group(1) if m else "Not found"

            spf_result = _grab('spf')
            dkim_result = _grab('dkim')
            dmarc_result = _grab('dmarc')

            # only trust A-R if it came from our configured boundary MTA
            if TRUSTED_AUTHSERV_ID and authserv_id.lower() == TRUSTED_AUTHSERV_ID.lower():
                ar_trusted = True

        analysis_results['Headers']['Auth_Serv_ID'] = authserv_id or "N/A"
        analysis_results['Headers']['SPF_Result'] = spf_result
        analysis_results['Headers']['DKIM_Result'] = dkim_result
        analysis_results['Headers']['DMARC_Result'] = dmarc_result
        analysis_results['Headers']['Auth_Results_Trusted'] = ar_trusted

        if ar_trusted:
            analysis_results['Headers']['Auth_Trust_Note'] = \
                f"Authentication-Results trusted (authserv-id: {authserv_id})."
        else:
            analysis_results['Headers']['Auth_Trust_Note'] = (
                "Authentication-Results NOT trusted - set TRUSTED_AUTHSERV_ID to your boundary MTA. "
                "SPF/DKIM/DMARC values below are informational only and excluded from the spoofing verdict."
            )

        # --- Spoofing verdict ---
        # domain alignment is always checked; auth results only count when trusted
        spoofing_detected = False
        spoofing_reasons = []

        if from_domain and rp_domain and from_domain != rp_domain:
            spoofing_detected = True
            spoofing_reasons.append(f"From domain ({from_domain}) != Return-Path domain ({rp_domain})")

        if ar_trusted:
            if dmarc_result == "fail":
                spoofing_detected = True
                spoofing_reasons.append("DMARC=fail")
            elif dmarc_result in ["neutral", "none", "temperror", "permerror"] and \
                    (spf_result == "fail" or dkim_result == "fail"):
                spoofing_detected = True
                spoofing_reasons.append("SPF or DKIM=fail with weak/absent DMARC")

        analysis_results['Headers']['Spoofing_Detected'] = spoofing_detected
        analysis_results['Headers']['Spoofing_Reasons'] = spoofing_reasons

        # geo + blacklist on the origin IP
        geo_info = get_geo_ip_info(origin_ip) if origin_ip != "No IP found in Received Header" else None
        analysis_results['Headers']['Origin_IP_Geo_Country'] = (geo_info or {}).get('country', "N/A")
        analysis_results['Headers']['Origin_IP_Geo_City'] = (geo_info or {}).get('city', "N/A")
        analysis_results['Headers']['Origin_IP_Geo_ISP'] = (geo_info or {}).get('isp', "N/A")
        analysis_results['Headers']['Origin_IP_Blacklist_Status'] = check_ip_blacklist(origin_ip)

        suspicious_subject_keywords = [
            "Important", "Account", "Password", "Order", "Invoice", "Win",
            "Urgent", "Security Alert", "Verify", "Update",
            "Suspended", "Payment", "Refund", "Unusual Activity", "Delivery",
            "Shipping", "Expired", "Notification", "Attention"
        ]
        found_subject_keywords = search_keywords_in_subject(
            analysis_results['Headers'].get('Subject'), suspicious_subject_keywords)
        analysis_results['Headers']['Suspicious_Subject_Keywords'] = \
            ", ".join(found_subject_keywords) if found_subject_keywords else "No suspicious keywords found"

        # --- Walk MIME parts: body, URLs, attachments ---
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            # plain-text body (first one only)
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                try:
                    current = part.get_payload(decode=True)
                    if current and not email_body:
                        email_body = current.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.debug("Error decoding text/plain part: %s", e)

            # html body: pull URLs + check for deceptive links
            elif ctype == 'text/html' and 'attachment' not in cdispo:
                try:
                    payload = part.get_payload(decode=True)
                    html_body = payload.decode('utf-8', errors='ignore') if payload else ""
                    soup = BeautifulSoup(html_body, 'html.parser')

                    for link in soup.find_all('a', href=True):
                        actual_url = link['href']
                        displayed_text = link.get_text().strip()
                        extracted_urls_from_html.append(actual_url)

                        # if the visible text looks like a URL but points to a different
                        # host than the href, that's a classic phishing tell
                        if displayed_text and re.match(r'https?://', displayed_text, re.IGNORECASE):
                            extracted_urls_from_html.append(displayed_text)
                            try:
                                disp_host = (urlparse(displayed_text).hostname or "").lower()
                                act_host = (urlparse(actual_url).hostname or "").lower()
                                if disp_host and act_host and disp_host != act_host:
                                    html_findings.append(
                                        f"Deceptive link: text shows '{disp_host}' but links to '{act_host}'")
                            except ValueError:
                                pass

                    # also collect URLs from src/href of other tags + css url()
                    for tag in soup.find_all(['img', 'script', 'iframe', 'link']):
                        if tag.name in ('img', 'script', 'iframe') and tag.has_attr('src'):
                            extracted_urls_from_html.append(tag['src'])
                        elif tag.name == 'link' and tag.has_attr('href'):
                            extracted_urls_from_html.append(tag['href'])

                    style_urls = re.findall(r'url\([\'"]?(.*?)[\'"]?\)', html_body)
                    extracted_urls_from_html.extend(style_urls)
                except Exception as e:
                    logger.debug("Error parsing HTML part: %s", e)

            # attachments
            if part.is_multipart():
                continue
            if part.get_filename() or 'attachment' in cdispo:
                file_name = part.get_filename()
                # fallback if get_filename() returns nothing
                if not file_name and 'attachment' in cdispo:
                    fname_match = re.search(r'filename\*?="?([^"]+)"?', cdispo)
                    if fname_match:
                        file_name = fname_match.group(1).strip()

                if file_name:
                    file_data = part.get_payload(decode=True)
                    if file_data is None:
                        continue

                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    full_attachment_dir = os.path.join(script_dir, ATTACHMENT_SAVE_DIR)
                    os.makedirs(full_attachment_dir, exist_ok=True)

                    # basename only - blocks path traversal via crafted filenames
                    sanitized_file_name = os.path.basename(file_name)
                    attachment_path = os.path.join(full_attachment_dir, sanitized_file_name)

                    try:
                        with open(attachment_path, 'wb') as att_file:
                            att_file.write(file_data)
                        analysis_results['Attachments'].append({
                            'filename': sanitized_file_name,
                            'size': len(file_data),
                            'path': attachment_path,
                            'hashes': calculate_file_hashes(attachment_path),
                            'static_analysis': analyze_attachment_static(attachment_path),
                            'virustotal_scan_status': "Skipped (API key not used)"
                        })
                    except Exception as e:
                        logger.error("Error saving attachment %s: %s", sanitized_file_name, e)
                        analysis_results['Attachments'].append({
                            'filename': sanitized_file_name,
                            'error': str(e),
                            'virustotal_scan_status': "Skipped (API key not used)"
                        })

        analysis_results['HTML_Findings'] = html_findings
        analysis_results['Body_Content'] = (email_body[:500] + "...") if len(email_body) > 500 else email_body

        # --- URL analysis (dedup text + html URLs, then score each) ---
        combined_urls = sorted(set(extract_urls_from_text(email_body) + extracted_urls_from_html))
        url_list = []
        for url in combined_urls:
            patterns, current_url_score = analyze_url_for_suspicious_patterns(url)
            url_info = {
                'url': url,
                'suspicious_patterns': patterns,
                'url_score': current_url_score,
                'whois_info': None,
                'virustotal_scan_status': "Skipped (API key not used)",
                'google_safe_browsing_status': check_url_google_safe_browsing(url)
            }
            host = urlparse(url).hostname
            if host:
                whois_data = get_whois_info(host)
                url_info['whois_info'] = whois_data if whois_data else "No WHOIS info found or lookups disabled"
            url_info['heuristic_verdict'] = get_heuristic_url_verdict(url_info)
            url_list.append(url_info)
        analysis_results['URLs'] = url_list

        analysis_results['Risk_Assessment'] = compute_overall_risk(analysis_results)

        return analysis_results

    except FileNotFoundError:
        logger.error("The email file '%s' was not found.", file_path)
        return None
    except Exception as e:
        logger.error("An unexpected error occurred during analysis: %s", e)
        traceback.print_exc()
        return None


# --- Output ---

def print_report(parsed_data, email_file):
    print("\n" + "=" * 60)
    print(f"|{'Analysis Results':^58}|")
    print("=" * 60)

    h = parsed_data['Headers']

    print("\n--- Header Information ---")
    print(f"{'Visual Sender (From):':<40} {h.get('From', 'N/A')}")
    print(f"{'Truth Sender Domain (Return-Path):':<40} {h.get('Return_Path_Domain', 'N/A')}")
    print(f"{'Truth Sender (Originating IP):':<40} {h.get('Origin_IP', 'N/A')}")
    print(f"{'Geo-Location:':<40} {h.get('Origin_IP_Geo_Country', 'N/A')}, {h.get('Origin_IP_Geo_City', 'N/A')}")
    print(f"{'ISP:':<40} {h.get('Origin_IP_Geo_ISP', 'N/A')}")
    print(f"{'IP Blacklist Status:':<40} {h.get('Origin_IP_Blacklist_Status', 'N/A')}")
    print("-" * 60)
    print(f"{'Recipient (To):':<40} {h.get('To', 'N/A')}")
    print(f"{'Subject:':<40} {h.get('Subject', 'N/A')}")
    print(f"{'Message-ID:':<40} {h.get('Message-ID', 'N/A')}")
    print(f"{'X-Mailer:':<40} {h.get('X-Mailer', 'N/A')}")
    print("-" * 60)
    print(f"{'Auth authserv-id:':<40} {h.get('Auth_Serv_ID', 'N/A')}")
    print(f"  {'SPF:':<37} {h.get('SPF_Result', 'N/A')}")
    print(f"  {'DKIM:':<37} {h.get('DKIM_Result', 'N/A')}")
    print(f"  {'DMARC:':<37} {h.get('DMARC_Result', 'N/A')}")
    print(f"  Trust: {h.get('Auth_Trust_Note', 'N/A')}")
    print("-" * 60)
    spoof = h.get('Spoofing_Detected', False)
    print(f"{'!!! SPOOFING DETECTED !!!':<40} {'YES' if spoof else 'No'}")
    for reason in h.get('Spoofing_Reasons', []):
        print(f"    - {reason}")
    print("-" * 60)
    print(f"{'Suspicious Subject Keywords:':<40} {h.get('Suspicious_Subject_Keywords', 'N/A')}")

    if parsed_data.get('HTML_Findings'):
        print("\n--- HTML / Deceptive Link Findings ---")
        for finding in parsed_data['HTML_Findings']:
            print(f"  - {finding}")

    print("\n--- URL Analysis ---")
    if isinstance(parsed_data.get('URLs'), list) and parsed_data['URLs']:
        for i, u in enumerate(parsed_data['URLs']):
            print(f"\n===== URL {i + 1}: {u['url']} =====")
            patterns = ', '.join(u['suspicious_patterns']) if u['suspicious_patterns'] else 'None found'
            print(f"  {'Suspicious Patterns:':<22} {patterns}")
            print(f"  {'URL Risk Score:':<22} {u['url_score']}")
            print(f"  {'Heuristic Verdict:':<22} {u.get('heuristic_verdict', 'N/A')}")
            print(f"  {'Google Safe Browsing:':<22} {u.get('google_safe_browsing_status', 'N/A')}")
            if isinstance(u.get('whois_info'), dict):
                print(f"  {'WHOIS Registrar:':<22} {u['whois_info'].get('registrar', 'N/A')}")
                cd = u['whois_info'].get('creation_date')
                if isinstance(cd, list):
                    cd = ", ".join(map(str, cd))
                print(f"  {'WHOIS Created:':<22} {cd if cd else 'N/A'}")
    else:
        print("No URLs found.")

    print("\n--- Attachment Analysis ---")
    if parsed_data.get('Attachments'):
        for i, a in enumerate(parsed_data['Attachments']):
            print(f"\n===== Attachment {i + 1}: {a.get('filename', 'N/A')} =====")
            if a.get('error'):
                print(f"  Error: {a['error']}")
            else:
                print(f"  Size: {a.get('size', 'N/A')} bytes")
                print(f"  SHA256: {a['hashes'].get('sha256', 'N/A')}")
                for finding in a.get('static_analysis', []):
                    print(f"  - {finding}")
    else:
        print("No attachments found.")

    ra = parsed_data.get('Risk_Assessment', {})
    print("\n" + "=" * 60)
    print(f"|{'Analysis Summary':^58}|")
    print("=" * 60)
    for alert in ra.get('alerts', []):
        print(f"  Risk Alert: {alert}")
    print(f"\nOverall Risk Score: {ra.get('score', 0)}")
    print(f"Verdict: {ra.get('verdict', 'N/A')}")
    print("=" * 60)


# --- Entry point ---

if __name__ == "__main__":
    email_file = ""
    while True:
        input_path = input("\nPlease enter the full path to the .eml file to analyze: ")
        input_path = input_path.strip().strip('"')
        if os.path.exists(input_path) and os.path.isfile(input_path):
            email_file = input_path
            break
        print(f"Error: '{input_path}' does not exist or is not a valid file. Please try again.")

    print(f"\n{'=' * 60}")
    print(f"|{'E-Mail Analysis Start':^58}|")
    print(f"|{('Analyzing: ' + os.path.basename(email_file)):<58}|")
    if not ENABLE_EXTERNAL_LOOKUPS:
        print(f"|{'External lookups DISABLED (opsec mode)':<58}|")
    print(f"{'=' * 60}")

    parsed_data = parse_email(email_file)

    if parsed_data:
        print_report(parsed_data, email_file)

        export_choice = input("\nExport the analysis results to a JSON file? (y/n): ").lower().strip()
        if export_choice == 'y':
            base = re.sub(r'[^\w\-_.]', '_', os.path.basename(email_file).replace('.eml', ''))
            output_json_filename = input(f"Filename (default '{base}_analysis.json'): ").strip()
            if not output_json_filename:
                output_json_filename = f"{base}_analysis.json"
            if not output_json_filename.lower().endswith('.json'):
                output_json_filename += '.json'
            export_results_to_json(parsed_data, output_json_filename)
        else:
            print("Results not exported.")

        print("\n--- Email Body (Excerpt, max. 500 chars) ---")
        print(parsed_data.get('Body_Content', 'No body content found.'))
        print("-" * 60)
    else:
        print("Email analysis could not be performed successfully.")
