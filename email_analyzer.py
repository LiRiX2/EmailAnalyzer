import email
from email import policy
from email.parser import BytesParser
import re
import requests
import whois  # Benötigt: pip install python-whois
from urllib.parse import urlparse  # Hilft beim Zerlegen von URLs
import hashlib  # Für Hash-Berechnungen
import os  # Für Dateisystemoperationen (Anhänge speichern)
from datetime import datetime, timedelta, timezone  # Für heuristische URL-Analyse (Domain-Alter)
import dateutil.parser  # Benötigt: pip install python-dateutil - für robustes Datums-Parsing
import traceback  # Für detaillierte Fehlermeldungen
import logging  # Statt stiller except:pass -> gezieltes Logging

# Oletools für erweiterte Anhangsanalyse
# Benötigt: pip install oletools
import oletools.olevba
from oletools.olevba import VBA_Parser  # Für VBA-Makro-Analyse

# BeautifulSoup für HTML-Parsing
# Benötigt: pip install beautifulsoup4
from bs4 import BeautifulSoup

# JSON für den Export der Ergebnisse
import json

# --- Logging ---
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger("email_analyzer")

# --- Konfiguration ---
# Pfad, unter dem Anhänge gespeichert werden sollen (relativ zum Skript)
ATTACHMENT_SAVE_DIR = "attachments_extracted"

# Opsec: Externe Lookups (Geo-IP, WHOIS) senden Indikatoren an Dritte.
# Über Umgebungsvariable steuerbar; Default = aktiviert.
#   EMAILANALYZER_EXTERNAL_LOOKUPS=0  -> deaktiviert (keine Daten an Dritte)
ENABLE_EXTERNAL_LOOKUPS = os.environ.get("EMAILANALYZER_EXTERNAL_LOOKUPS", "1") != "0"

# Vertrauensgrenze für Authentication-Results (RFC 8601):
# Nur der A-R-Header der EIGENEN, empfangenden MTA ist vertrauenswürdig - ein Angreifer
# kann in der rohen Mail beliebige A-R-Header faelschen. Trage hier die authserv-id eurer
# empfangenden MTA ein (z. B. "mx.example.com"). Bleibt das leer, werden A-R-Header als
# NICHT vertrauenswürdig behandelt und fliessen nicht in den Spoofing-Verdict ein.
TRUSTED_AUTHSERV_ID = os.environ.get("EMAILANALYZER_TRUSTED_AUTHSERV_ID", "")


# --- Hilfsfunktionen für IP- und Keyword-Analyse ---

def get_geo_ip_info(ip_address):
    """
    Ruft Geo-IP-Informationen für eine gegebene IP-Adresse ab (ip-api.com).
    Wird nur ausgeführt, wenn externe Lookups erlaubt sind (Opsec).
    """
    if not ENABLE_EXTERNAL_LOOKUPS:
        return None
    if not ip_address or ip_address == "No IP found in Received Header":
        return None

    # Hinweis: Der kostenlose ip-api.com-Endpunkt ist nur über HTTP verfügbar
    # (kein TLS). Für produktive Nutzung lokale GeoLite2-DB oder bezahlte HTTPS-API.
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
    """
    Vereinfachter Blacklist-Check (Platzhalter für eine echte RBL/Threat-Intel-Anbindung).
    """
    if not ip_address or ip_address == "No IP found in Received Header":
        return "N/A"

    if ip_address == "192.0.2.1":
        return "Known Test IP (Highly Suspicious)"  # reservierte Test-IP (RFC 5737)
    elif ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172.16."):
        return "Private IP (Internal Network, Not Publicly Routable)"
    elif ip_address.startswith("1.2.3."):
        return "Suspicious Subnet (Demo Example)"
    else:
        return "Clean (No specific blacklist hit in demo / Public IP)"


def search_keywords_in_subject(subject, keywords):
    """
    Sucht nach verdächtigen Keywords im Betreff - mit Wortgrenzen, um
    Substring-Fehltreffer zu vermeiden (z. B. "Win" in "showing").
    """
    if not subject:
        return []

    found_keywords = []
    subject_lower = subject.lower()
    for keyword in keywords:
        if re.search(r'\b' + re.escape(keyword.lower()) + r'\b', subject_lower):
            found_keywords.append(keyword)
    return found_keywords


# --- Funktionen für URL-Analyse ---

def extract_urls_from_text(text):
    """
    Extrahiert URLs aus einem Text. Bewusst einfacher, robuster Regex
    (greift alles ab dem Schema bis zum nächsten Whitespace/Trennzeichen).
    """
    if not text:
        return []
    url_pattern = re.compile(
        r'(?:https?|ftp|file)://'      # Schema
        r'[^\s<>"\')\]]+',             # bis zum nächsten Whitespace / schliessenden Zeichen
        re.IGNORECASE
    )
    # Häufige nachlaufende Satzzeichen abschneiden
    return [u.rstrip('.,);\'"') for u in url_pattern.findall(text)]


def get_whois_info(domain):
    """
    Ruft WHOIS-Informationen ab. Nur bei erlaubten externen Lookups (Opsec).
    """
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
    """
    Analysiert eine URL auf verdächtige Muster und weist einen Risikowert zu.
    """
    suspicious_patterns = []
    url_score = 0

    parsed_url = urlparse(url)
    # hostname() entfernt Port und Userinfo -> robuster als netloc
    host = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    # 1. IP-Adresse als Domain (IPv4 oder IPv6-Literal)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) or \
            re.match(r'^[0-9a-fA-F:]+$', host) and ':' in host:
        suspicious_patterns.append("IP as domain")
        url_score += 3

    # 2. Sehr langer Query-Parameter (mögliche Verschleierung)
    if len(query) > 100:
        suspicious_patterns.append(f"Long query ({len(query)} chars)")
        url_score += 2

    # 3. Verdächtige Keywords in Pfad/Query
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
    """
    Heuristische Einschätzung des URL-Risikos (Score + WHOIS), ohne externe Reputations-APIs.
    """
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
                # FIX: naive/aware-Mischfehler vermeiden -> beides auf tz-aware UTC normalisieren
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
    """
    Platzhalter für die Google Safe Browsing API (kein API-Key in der öffentlichen Version).
    """
    if api_key:
        # Hier würde die tatsächliche API-Anfrage stehen (threatMatches:find).
        return "SKIPPED (Google Safe Browsing - API key available but not implemented)"
    else:
        return "SKIPPED (Google Safe Browsing - API key not provided)"


def export_results_to_json(data, output_filename):
    """
    Exportiert die Analysedaten als JSON. datetime-Objekte werden in ISO-Strings konvertiert.
    """
    try:
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


# --- Funktionen für Dateianhang-Analyse ---

def calculate_file_hashes(file_path):
    """
    Berechnet MD5, SHA1 und SHA256 einer Datei.
    """
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
    """
    Einfache statische Analyse eines Anhangs, inkl. Makro-Analyse für Office-Dokumente (oletools).
    """
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


# --- Header-Hilfsfunktion: Domain aus einer Adresse ziehen ---

def _extract_domain(value):
    if not value:
        return None
    m = re.search(r'@([a-zA-Z0-9.-]+)', value)
    return m.group(1).lower().rstrip('.>') if m else None


# --- Risikobewertung (zentral, damit der Score auch im JSON landet) ---

def compute_overall_risk(parsed_data):
    """
    Berechnet den konsolidierten Risk Score + Verdict aus allen Befunden.
    Gibt ein Dict zurück, das in parsed_data gespeichert (und damit exportiert) wird.
    """
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

    # Deceptive link findings (Anzeigetext != Ziel-Domain)
    for finding in parsed_data.get('HTML_Findings', []):
        alerts.append(f"{finding} (High Risk)")
        risk_score += 3

    url_total = 0
    if isinstance(parsed_data.get('URLs'), list):
        for url_entry in parsed_data['URLs']:
            if url_entry.get('url_score', 0) > 0:
                url_total += url_entry['url_score']
    if url_total > 0:
        risk_score += (url_total // 2) + 1

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


# --- Hauptfunktion zum Parsen und Analysieren der E-Mail ---

def parse_email(file_path):
    """
    Parst eine .eml-Datei, extrahiert Header/IPs/URLs/Anhänge und analysiert sie.
    """
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

        # --- HEADER-ANALYSE ---
        analysis_results['Headers'] = {
            'From': msg.get('From'),
            'To': msg.get('To'),
            'Subject': msg.get('Subject'),
            'Message-ID': msg.get('Message-ID'),
            'X-Mailer': msg.get('X-Mailer')
        }

        # Ursprungs-IP aus Received-Headern
        received_headers = msg.get_all('Received')
        origin_ip = "No IP found in Received Header"
        if received_headers:
            for received_header in reversed(received_headers):
                ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_header)
                if ip_match:
                    origin_ip = ip_match.group(1)
                    break
            if origin_ip == "No IP found in Received Header":
                for received_header in reversed(received_headers):
                    ip_match_direct = re.search(r'(?:from|by)\s+\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                                                received_header)
                    if ip_match_direct:
                        origin_ip = ip_match_direct.group(1)
                        break
        analysis_results['Headers']['Origin_IP'] = origin_ip

        # Absenderdomain (From) und Return-Path-Domain
        from_domain = _extract_domain(analysis_results['Headers']['From'])
        analysis_results['Headers']['Sender_Domain'] = from_domain or "Not available"

        return_path = msg.get('Return-Path')
        rp_domain = _extract_domain(return_path)
        analysis_results['Headers']['Return_Path_Domain'] = rp_domain or (return_path or "Not found")

        # --- AUTHENTICATION-RESULTS (mit Trust-Boundary) ---
        # WICHTIG: A-R-Header sind nur vertrauenswürdig, wenn sie von der eigenen
        # empfangenden MTA stammen (authserv-id). Wir nehmen den OBERSTEN A-R-Header
        # (zuletzt von der empfangenden Infrastruktur vorangestellt).
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

        # --- SPOOFING-VERDICT: Domain-Alignment (immer) + Auth (nur wenn vertrauenswürdig) ---
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

        # Geo-IP und Blacklist
        geo_info = get_geo_ip_info(origin_ip) if origin_ip != "No IP found in Received Header" else None
        analysis_results['Headers']['Origin_IP_Geo_Country'] = (geo_info or {}).get('country', "N/A")
        analysis_results['Headers']['Origin_IP_Geo_City'] = (geo_info or {}).get('city', "N/A")
        analysis_results['Headers']['Origin_IP_Geo_ISP'] = (geo_info or {}).get('isp', "N/A")
        analysis_results['Headers']['Origin_IP_Blacklist_Status'] = check_ip_blacklist(origin_ip)

        # Verdächtige Keywords im Betreff
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

        # --- BODY-, URL- UND ANHANGS-EXTRAKTION ---
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            # 1. Text-Body (erster text/plain-Part)
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                try:
                    current = part.get_payload(decode=True)
                    if current and not email_body:
                        email_body = current.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.debug("Error decoding text/plain part: %s", e)

            # 2. HTML-Body: URLs + Deceptive-Link-Erkennung
            elif ctype == 'text/html' and 'attachment' not in cdispo:
                try:
                    payload = part.get_payload(decode=True)
                    html_body = payload.decode('utf-8', errors='ignore') if payload else ""
                    soup = BeautifulSoup(html_body, 'html.parser')

                    for link in soup.find_all('a', href=True):
                        actual_url = link['href']
                        displayed_text = link.get_text().strip()
                        extracted_urls_from_html.append(actual_url)

                        # FIX: echte Deceptive-Link-Erkennung
                        # Wenn der sichtbare Text wie eine URL aussieht und auf eine ANDERE
                        # Domain zeigt als das tatsächliche href, ist das ein Phishing-Indikator.
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

                    for tag in soup.find_all(['img', 'script', 'iframe', 'link']):
                        if tag.name in ('img', 'script', 'iframe') and tag.has_attr('src'):
                            extracted_urls_from_html.append(tag['src'])
                        elif tag.name == 'link' and tag.has_attr('href'):
                            extracted_urls_from_html.append(tag['href'])

                    style_urls = re.findall(r'url\([\'"]?(.*?)[\'"]?\)', html_body)
                    extracted_urls_from_html.extend(style_urls)
                except Exception as e:
                    logger.debug("Error parsing HTML part: %s", e)

            # 3. Anhänge
            if part.is_multipart():
                continue
            if part.get_filename() or 'attachment' in cdispo:
                file_name = part.get_filename()
                # get_filename() behandelt RFC 2231 bereits; einfacher Fallback:
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

                    # Path-Traversal-Schutz: nur Basisname verwenden
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

        # --- URL-ANALYSE ---
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

        # --- KONSOLIDIERTER RISK SCORE (jetzt Teil der Ergebnisse -> auch im JSON) ---
        analysis_results['Risk_Assessment'] = compute_overall_risk(analysis_results)

        return analysis_results

    except FileNotFoundError:
        logger.error("The email file '%s' was not found.", file_path)
        return None
    except Exception as e:
        logger.error("An unexpected error occurred during analysis: %s", e)
        traceback.print_exc()
        return None


# --- Ausgabe ---

def print_report(parsed_data, email_file):
    print("\n" + "=" * 60)
    print(f"|{'Analysis Results':^58}|")
    print("=" * 60)

    h = parsed_data['Headers']

    # 1. HEADER
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

    # 2. DECEPTIVE LINKS
    if parsed_data.get('HTML_Findings'):
        print("\n--- HTML / Deceptive Link Findings ---")
        for finding in parsed_data['HTML_Findings']:
            print(f"  - {finding}")

    # 3. URLs
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

    # 4. ATTACHMENTS
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

    # 5. SUMMARY
    ra = parsed_data.get('Risk_Assessment', {})
    print("\n" + "=" * 60)
    print(f"|{'Analysis Summary':^58}|")
    print("=" * 60)
    for alert in ra.get('alerts', []):
        print(f"  Risk Alert: {alert}")
    print(f"\nOverall Risk Score: {ra.get('score', 0)}")
    print(f"Verdict: {ra.get('verdict', 'N/A')}")
    print("=" * 60)


# --- Hauptteil ---

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
