import email
from email import policy
from email.parser import BytesParser
import re
import requests
import whois  # Benötigt: pip install python-whois
from urllib.parse import urlparse  # Hilft beim Zerlegen von URLs
import hashlib  # Neu hinzugefügt für Hash-Berechnungen
import os  # Neu hinzugefügt für Dateisystemoperationen (Anhänge speichern)
from datetime import datetime, timedelta  # Für heuristische URL-Analyse (Domain-Alter)
import dateutil.parser  # Benötigt: pip install python-dateutil - für robustes Datums-Parsing
import traceback  # Neu hinzugefügt für detaillierte Fehlermeldungen

# Oletools für erweiterte Anhangsanalyse
# Benötigt: pip install oletools
import oletools.olevba
from oletools.olevba import VBA_Parser  # Für VBA-Makro-Analyse

# BeautifulSoup für HTML-Parsing
# Benötigt: pip install beautifulsoup4
from bs4 import BeautifulSoup

# JSON für den Export der Ergebnisse
import json  # Neu hinzugefügt für JSON-Export

# --- Konfiguration ---
# Pfad, unter dem Anhänge gespeichert werden sollen (relativ zum Skript)
ATTACHMENT_SAVE_DIR = "attachments_extracted"


# --- Hilfsfunktionen für IP- und Keyword-Analyse ---

def get_geo_ip_info(ip_address):
    """
    Ruft Geo-IP-Informationen für eine gegebene IP-Adresse ab.
    Verwendet die öffentliche API von ip-api.com.

    Args:
        ip_address (str): Die IP-Adresse, die überprüft werden soll.

    Returns:
        dict: Ein Wörterbuch mit Geo-IP-Informationen (Land, Stadt, ISP) oder None bei Fehler.
    """
    if not ip_address or ip_address == "No IP found in Received Header":
        return None

    # ip-api.com ist kostenlos für nicht-kommerzielle Nutzung und hat ein Rate Limit (45 Anfragen/Minute).
    # Für produktive Umgebungen ggf. auf eine kostenpflichtige API oder eine lokale GeoLite2-Datenbank umsteigen.
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(url, timeout=5)  # Timeout von 5 Sekunden, um Hängenbleiben zu vermeiden
        response.raise_for_status()  # Löst einen HTTPError für schlechte Antworten (4xx oder 5xx) aus
        data = response.json()

        if data and data.get('status') == 'success':
            return {
                'country': data.get('country'),
                'city': data.get('city'),
                'isp': data.get('isp')
            }
        else:
            print(f"Geo-IP-API-Error for {ip_address}: {data.get('message', 'Unknown error')}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error during Geo-IP query for {ip_address}: {e}")
        return None


def check_ip_blacklist(ip_address):
    """
    Führt einen (vereinfachten) Blacklist-Check für eine gegebene IP-Adresse durch.
    Dies ist ein Platzhalter für eine erweiterte Implementierung mit externen APIs.
    """
    if not ip_address or ip_address == "No IP found in Received Header":
        return "N/A"

    if ip_address == "192.0.2.1":
        return "Known Test IP (Highly Suspicious)"  # Dies ist eine reservierte Test-IP
    elif ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172.16."):
        return "Private IP (Internal Network, Not Publicly Routable)"
    elif ip_address.startswith("1.2.3."):
        return "Suspicious Subnet (Demo Example)"
    else:
        return "Clean (No specific blacklist hit in demo / Public IP)"


def search_keywords_in_subject(subject, keywords):
    """
    Sucht nach verdächtigen Keywords im E-Mail-Betreff.

    Args:
        subject (str): Der Betreff der E-Mail.
        keywords (list): Eine Liste von Keywords, nach denen gesucht werden soll.

    Returns:
        list: Eine Liste der gefundenen Keywords. Gibt eine leere Liste zurück, wenn keine gefunden wurden.
    """
    if not subject:
        return []

    found_keywords = []
    # Konvertiere den Betreff zu Kleinbuchstaben für eine case-insensitive Suche
    subject_lower = subject.lower()
    for keyword in keywords:
        if keyword.lower() in subject_lower:
            found_keywords.append(keyword)
    return found_keywords


# --- Funktionen für URL-Analyse ---

def extract_urls_from_text(text):
    """
    Extrahiert URLs aus einem gegebenen Text.
    Verwendet einen regulären Ausdruck, der HTTP(S)-URLs, FTP, file://, etc. erkennt.
    """
    # Verbesserter Regex für URLs: erkennt http/https/ftp/file Schemas
    # und einfache Domains/IPs mit Pfaden
    url_pattern = re.compile(
        r'(?:https?|ftp|file)://'  # Protokoll
        r'(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'  # Domain/IP und Pfad
        r'(?:\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)*'  # Weitere Domainteile
        r'(?:/[a-zA-Z0-9$-_@.&+!*\\(\\),%]*)*/?'  # Optionale Pfade
        r'(?:\?[a-zA-Z0-9$-_@.&+!*\\(\\),%=\?:]*)?'  # Optionale Query-Parameter
        r'(?:#[a-zA-Z0-9$-_@.&+!*\\(\\),%:]*)?'  # Optionaler Fragment-Identifier
    )
    return url_pattern.findall(text)


def get_whois_info(domain):
    """
    Ruft WHOIS-Informationen für eine gegebene Domain ab.
    Benötigt die 'python-whois' Bibliothek.
    """
    try:
        w = whois.whois(domain)
        # whois-Objekt kann None sein, wenn keine Daten gefunden wurden
        if w:
            # Einige nützliche WHOIS-Felder
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
        # print(f"Error during WHOIS query for {domain}: {e}") # For debugging
        return None


def analyze_url_for_suspicious_patterns(url):
    """
    Analysiert eine URL auf verdächtige Muster und weist einen Risikowert zu.
    Die zurückgegebenen Strings sind prägnanter für die Ausgabe.
    """
    suspicious_patterns = []
    url_score = 0  # NEU: Initialisiere den Score für diese URL

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    # 1. IP-Adresse als Domain (z.B. http://192.168.1.1/malicious)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) or \
            re.match(r'^\[[0-9a-fA-F:]+\]$', domain):  # IPv6
        suspicious_patterns.append("IP as domain")
        url_score += 3  # HOHER RISIKOWERT

    # 2. Sehr langer Query-Parameter (könnte Verschleierung sein)
    if len(query) > 100:  # Schwellenwert anpassbar
        suspicious_patterns.append(f"Long query ({len(query)} chars)")
        url_score += 2  # MITTLERER RISIKOWERT

    # 3. Keyword in URL-Pfad (z.B. login, update, verify, admin)
    suspicious_url_keywords = ["login", "update", "verify", "admin", "account", "security", "alert",
                               "bank", "paypal", "invoice", "payment", "support", "amazon", "apple",
                               "microsoft", "icloud", "dropbox", "onedrive"]
    for keyword in suspicious_url_keywords:
        # Hier fügen wir nur das Keyword hinzu, wenn es gefunden wird
        if keyword.lower() in path.lower() or keyword.lower() in query.lower():
            if keyword not in suspicious_patterns:  # Vermeide Duplikate
                suspicious_patterns.append(keyword)
                url_score += 1  # GERINGERER RISIKOWERT PRO KEYWORD

    # Später hier VirusTotal-Ergebnisse und andere Checks mit weiteren Punkten hinzufügen

    return suspicious_patterns, url_score  # Gib beides zurück


def get_heuristic_url_verdict(url_entry):
    """
    Gibt eine heuristische Einschätzung des URL-Risikos basierend auf dem Score
    und WHOIS-Informationen (ohne externe API-Abfragen wie VirusTotal).

    Args:
        url_entry (dict): Ein Wörterbuch mit der URL-Analyse (inkl. url_score, whois_info).

    Returns:
        str: Eine heuristische Einschätzung wie "Malicious (Heuristic)", "Suspicious (Heuristic)", "Potentially Clean (Heuristic)".
    """
    score = url_entry.get('url_score', 0)
    whois_info = url_entry.get('whois_info')

    # Höchste Priorität: IP-Adresse als Domain
    if "IP as domain" in url_entry.get('suspicious_patterns', []):
        return "Malicious (IP as domain - Heuristic)"

    # Hoher Score deutet auf hohe Verdächtigkeit hin
    if score >= 3:  # Beispiel-Schwellenwert
        return "Malicious (High Score - Heuristic)"
    elif score >= 1:
        return "Suspicious (Medium Score - Heuristic)"

    # Analyse basierend auf WHOIS-Daten, wenn verfügbar
    if isinstance(whois_info, dict):
        creation_date = whois_info.get('creation_date')
        if isinstance(creation_date, list):  # WHOIS-Datum kann als Liste zurückkommen
            creation_date = creation_date[0] if creation_date else None

        if creation_date:
            try:
                # Versuche, das Datum zu parsen. dateutil.parser ist robuster.
                parsed_creation_date = dateutil.parser.parse(str(creation_date))

                # Überprüfe, ob Domain sehr jung ist (z.B. weniger als 30 Tage alt)
                # Aktuelles Datum berücksichtigen (für dynamische Tests)
                if datetime.now() - parsed_creation_date < timedelta(days=30):
                    return "Highly Suspicious (Very Young Domain - Heuristic)"
            except Exception:
                pass  # Fehler beim Parsen des Datums ignorieren

    # Wenn nichts Gravierendes gefunden wurde
    if score == 0:
        return "Potentially Clean (Heuristic)"

    return "Unknown (Heuristic)"  # Falls ein Score, aber keine spezifische Regel zutrifft


def check_url_google_safe_Browse(url, api_key=None):
    """
    Platzhalter für die Abfrage der Google Safe Browse API.
    Benötigt einen API-Key und eine tatsächliche Implementierung.

    Args:
        url (str): Die zu überprüfende URL.
        api_key (str): Ihr Google Safe Browse API-Key (optional für diesen Platzhalter).

    Returns:
        str: Scan-Status von Google Safe Browse (z.B. "MALICIOUS", "CLEAN", "SKIPPED").
    """
    if api_key:
        # Hier würde die tatsächliche API-Anfrage an Google Safe Browse stehen.
        # Beispiel:
        # try:
        #     api_url = f"https://safeBrowse.googleapis.com/v4/threatMatches:find?key={api_key}"
        #     payload = {
        #         "client": {"clientId": "your-app-name", "clientVersion": "1.0"},
        #         "threatInfo": {
        #             "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIELLY_HARMFUL_APPLICATION"],
        #             "platformTypes": ["ANY_PLATFORM"],
        #             "threatEntryTypes": ["URL"],
        #             "threatEntries": [{"url": url}]
        #         }
        #     }
        #     response = requests.post(api_url, json=payload, timeout=10)
        #     response.raise_for_status()
        #     threat_matches = response.json().get('matches', [])
        #     if threat_matches:
        #         # Hier müsste man die Matches parsen und einen Status zurückgeben
        #         return f"MALICIOUS (GSB: {threat_matches[0]['threatType']})"
        #     else:
        #         return "CLEAN (GSB)"
        # except requests.exceptions.RequestException as e:
        #     return f"ERROR (GSB API): {e}"
        # except Exception as e:
        #     return f"ERROR (GSB Processing): {e}"
        return "SKIPPED (Google Safe Browse - API Key available but not implemented)"
    else:
        return "SKIPPED (Google Safe Browse - API Key not provided)"


def export_results_to_json(data, output_filename):
    """
    Exportiert die Analysedaten in eine JSON-Datei.
    Konvertiert datetime-Objekte in ISO-formatierte Strings für JSON-Kompatibilität.

    Args:
        data (dict): Das Wörterbuch mit den Analysedaten.
        output_filename (str): Der Name der Ausgabedatei (z.B. 'analyse_ergebnisse.json').
    """
    try:
        # Rekursive Funktion, um datetime-Objekte zu konvertieren
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
            # indent=4 sorgt für eine schön formatierte, lesbare JSON-Datei
            # ensure_ascii=False erlaubt nicht-ASCII-Zeichen direkt (z.B. Umlaute),
            # anstatt sie in Escape-Sequenzen zu konvertieren (\u00fc)
            json.dump(serializable_data, f, indent=4, ensure_ascii=False)
        print(f"\nResults successfully exported to '{output_filename}'")
    except Exception as e:
        print(f"\nError exporting results to JSON: {e}")
        traceback.print_exc()  # Für detaillierteres Debugging


# --- Funktionen für Dateianhang-Analyse ---

def calculate_file_hashes(file_path):
    """
    Berechnet MD5, SHA1 und SHA256 Hashes einer Datei.
    """
    hashes = {
        'md5': '',
        'sha1': '',
        'sha256': ''
    }
    try:
        with open(file_path, 'rb') as f:
            bytes_content = f.read()
            hashes['md5'] = hashlib.md5(bytes_content).hexdigest()
            hashes['sha1'] = hashlib.sha1(bytes_content).hexdigest()
            hashes['sha256'] = hashlib.sha256(bytes_content).hexdigest()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found for hash calculation.")
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
    return hashes


def analyze_attachment_static(file_path):
    """
    Führt eine einfache statische Analyse eines Dateianhangs durch.
    Erweitert um Makro-Analyse für Office-Dokumente mittels oletools.
    """
    analysis_results = []
    file_name = os.path.basename(file_path)
    file_extension = os.path.splitext(file_name)[1].lower()  # Dateiendung extrahieren

    # Erkennung von ausführbaren Dateien und Skripten (bestehend)
    if file_extension in ('.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1'):
        analysis_results.append("Executable file detected. HIGHLY SUSPICIOUS!")
    elif file_extension in ('.js', '.vbs', '.hta'):
        analysis_results.append("Script file detected. Potentially suspicious.")

    # NEU: Erweiterte Office-Dokument-Analyse mit oletools
    if file_extension in ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.docm', '.xlsm', '.pptm'):
        try:
            # VBA_Parser erwartet den Dateipfad als String.
            vba_parser = VBA_Parser(file_path)

            # oletools wirft selbst Exceptions, wenn die Datei kein gültiges OLE/OpenXML ist.
            # Die 'is_valid_doc'-Prüfung wird entfernt, da sie in manchen oletools-Versionen fehlt.

            if vba_parser.detect_vba_macros():
                analysis_results.append("Office document contains VBA macros. HIGHLY SUSPICIOUS!")

                # Optional: Extrahieren und Zusammenfassen der Makro-Informationen
                auto_exec_macros = []
                for (filename_in_doc, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    if vba_code:
                        if re.search(
                                r'autoopen|autoclose|workbook_open|document_open|document_close|autoexec|sub auto_open|sub auto_close|sub workbook_open|sub document_open|sub document_close',
                                vba_code, re.IGNORECASE):
                            auto_exec_macros.append(vba_filename)

                if auto_exec_macros:
                    analysis_results.append(f"  - Auto-executing macros found in: {', '.join(auto_exec_macros)}")
            else:
                analysis_results.append("Office document found, no VBA macros detected.")

            vba_parser.close()  # Wichtig: Parser schließen, um Datei-Handles freizugeben

        except Exception as e:
            # Dieser generische Fehler fängt jetzt alle oletools-spezifischen Probleme ab
            # (z.B. wenn die Datei kein gültiges OLE/OpenXML-Format ist oder andere Parser-Fehler).
            analysis_results.append(f"Could not analyze Office document with oletools: {e}")
            # traceback.print_exc() # Kann hier für tiefere Fehleranalyse aktiviert werden

    if not analysis_results:
        analysis_results.append("No specific static analysis findings.")

    return analysis_results


# --- Hauptfunktion zum Parsen und Analysieren der E-Mail ---

def parse_email(file_path):
    """
    Parst eine .eml-Datei, extrahiert Header-Informationen, IPs, URLs und analysiert diese.
    Erweitert um Dateianhang-Analyse.

    Args:
        file_path (str): Der Pfad zur .eml-Datei.

    Returns:
        dict: Ein Wörterbuch mit allen extrahierten und analysierten Informationen oder None bei Fehler.
    """
    # Sicherstellen, dass msg, email_body und analysis_results immer definiert sind
    msg = None
    email_body = ""
    # Initialisiere analysis_results mit allen erwarteten Top-Level-Keys, um Fehler zu vermeiden
    analysis_results = {
        'Headers': {},
        'URLs': [],
        'Attachments': [],
        'Body_Content': ""
    }
    extracted_urls_from_html = []  # Initialisierung für HTML-URLs

    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # analysis_results neu initialisieren nach erfolgreichem Parsen der E-Mail
        analysis_results = {}
        analysis_results['Attachments'] = []

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

        # Absenderdomain aus From-Header
        if analysis_results['Headers']['From']:
            domain_match = re.search(r'@([a-zA-Z0-9.-]+)', analysis_results['Headers']['From'])
            if domain_match:
                analysis_results['Headers']['Sender_Domain'] = domain_match.group(1)
            else:
                analysis_results['Headers']['Sender_Domain'] = "Not found in From Header"
        else:
            analysis_results['Headers']['Sender_Domain'] = "Not available"

        # Extrahiere Return-Path (oft der "Envelope From" oder "Mail From" Absender)
        return_path = msg.get('Return-Path')
        if return_path:
            # Versuche, die Domain aus dem Return-Path zu extrahieren
            return_path_domain_match = re.search(r'@([a-zA-Z0-9.-]+)', return_path)
            if return_path_domain_match:
                analysis_results['Headers']['Return_Path_Domain'] = return_path_domain_match.group(1)
            else:
                # Manchmal ist der Return-Path nur eine E-Mail-Adresse ohne Domain, oder leer
                analysis_results['Headers']['Return_Path_Domain'] = return_path  # Speichere den gesamten Return-Path
        else:
            analysis_results['Headers']['Return_Path_Domain'] = "Not found"

        # SPF, DKIM, DMARC-Ergebnisse
        auth_results = msg.get('Authentication-Results')
        if auth_results:
            analysis_results['Headers']['SPF_Result'] = re.search(r'spf=(\w+)', auth_results).group(1) if re.search(
                r'spf=(\w+)', auth_results) else "Not found"
            analysis_results['Headers']['DKIM_Result'] = re.search(r'dkim=(\w+)', auth_results).group(1) if re.search(
                r'dkim=(\w+)', auth_results) else "Not found"
            analysis_results['Headers']['DMARC_Result'] = re.search(r'dmarc=(\w+)', auth_results).group(1) if re.search(
                r'dmarc=(\w+)', auth_results) else "Not found"
        else:
            analysis_results['Headers']['SPF_Result'] = "Not available"
            analysis_results['Headers']['DKIM_Result'] = "Not available"
            analysis_results['Headers']['DMARC_Result'] = "Not available"

        # Basis-Spoofing-Check
        spoofing_detected = False
        dmarc_result = analysis_results['Headers'].get('DMARC_Result', 'Not available')
        spf_result = analysis_results['Headers'].get('SPF_Result', 'Not available')
        dkim_result = analysis_results['Headers'].get('DKIM_Result', 'Not available')

        if dmarc_result == "fail":
            spoofing_detected = True
        elif dmarc_result in ["neutral", "none", "temperror", "permerror"] and (
                spf_result == "fail" or dkim_result == "fail"):
            spoofing_detected = True

        analysis_results['Headers']['Spoofing_Detected'] = spoofing_detected

        # Geo-IP und Blacklist für Origin_IP
        if analysis_results['Headers'].get('Origin_IP') and analysis_results['Headers'][
            'Origin_IP'] != "No IP found in Received Header":
            geo_info = get_geo_ip_info(analysis_results['Headers']['Origin_IP'])
            if geo_info:
                analysis_results['Headers']['Origin_IP_Geo_Country'] = geo_info.get('country')
                analysis_results['Headers']['Origin_IP_Geo_City'] = geo_info.get('city')
                analysis_results['Headers']['Origin_IP_Geo_ISP'] = geo_info.get('isp')
            else:
                analysis_results['Headers']['Origin_IP_Geo_Country'] = "N/A"
                analysis_results['Headers']['Origin_IP_Geo_City'] = "N/A"
                analysis_results['Headers']['Origin_IP_Geo_ISP'] = "N/A"
        else:
            analysis_results['Headers']['Origin_IP_Geo_Country'] = "N/A"
            analysis_results['Headers']['Origin_IP_Geo_City'] = "N/A"
            analysis_results['Headers']['Origin_IP_Geo_ISP'] = "N/A"

        analysis_results['Headers']['Origin_IP_Blacklist_Status'] = check_ip_blacklist(
            analysis_results['Headers']['Origin_IP'])

        # Verdächtige Keywords im Betreff suchen
        suspicious_subject_keywords = [
            "Important", "Account", "Password", "Order", "Invoice", "Win",
            "Urgent", "Security Alert", "Verify", "Update",
            "Suspended", "Payment", "Refund", "Unusual Activity", "Delivery",
            "Shipping", "Expired", "Notification", "Attention"
        ]
        found_subject_keywords = search_keywords_in_subject(analysis_results['Headers'].get('Subject'),
                                                            suspicious_subject_keywords)
        if found_subject_keywords:
            analysis_results['Headers']['Suspicious_Subject_Keywords'] = ", ".join(found_subject_keywords)
        else:
            analysis_results['Headers']['Suspicious_Subject_Keywords'] = "No suspicious keywords found"

        # --- E-MAIL-BODY-EXTRAKTION & ANHANGS-EXTRAKTION ---
        # email_body wurde bereits initialisiert zu Beginn der Funktion (falls kein Text-Part gefunden wird)
        # extracted_urls_from_html wurde bereits initialisiert

        # Gehe alle Teile der E-Mail durch (walk() durchläuft alle Sub-Parts)
        # msg.walk() ist für die rekursive Durchsuchung am besten geeignet
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            # 1. Text-Body extrahieren (bevorzugt text/plain)
            # Nur den ersten text/plain-Teil als Haupt-Body nehmen, wenn nicht als Anhang gekennzeichnet
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                try:
                    current_part_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    if not email_body:  # Füge nur hinzu, wenn email_body noch leer ist (d.h. erster Klartext-Part)
                        email_body = current_part_body
                except Exception as e:
                    print(f"Error decoding text/plain part: {e}")

            # NEU: HTML-Body extrahieren und URLs parsen
            elif ctype == 'text/html' and 'attachment' not in cdispo:
                try:
                    html_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    soup = BeautifulSoup(html_body, 'html.parser')

                    # URLs aus <a> Tags extrahieren
                    for link in soup.find_all('a', href=True):
                        actual_url = link['href']
                        displayed_text = link.get_text().strip()

                        # Prüfen auf sichtbare Abweichung (Phishing)
                        if displayed_text and actual_url and actual_url != displayed_text:
                            # Wenn der sichtbare Text eine URL ähnelt, fügen wir diese auch zur Analyse hinzu
                            if re.match(r'https?://', displayed_text):
                                extracted_urls_from_html.append(displayed_text)
                            # Manchmal sind auch einfach nur die Domains unterschiedlich
                            try:
                                if urlparse(actual_url).netloc != urlparse(displayed_text).netloc:
                                    # Optional: print(f"Domain mismatch: Displayed '{urlparse(displayed_text).netloc}' vs Actual '{urlparse(actual_url).netloc}'")
                                    pass
                            except ValueError:  # Bei ungültigen URLs in Text oder href
                                pass

                        extracted_urls_from_html.append(actual_url)  # Immer die eigentliche URL hinzufügen

                    # URLs aus <img>, <script src>, <link href>, <iframe src> etc.
                    for tag in soup.find_all(['img', 'script', 'iframe', 'link']):
                        if tag.name == 'img' and tag.has_attr('src'):
                            extracted_urls_from_html.append(tag['src'])
                        if tag.name == 'script' and tag.has_attr('src'):
                            extracted_urls_from_html.append(tag['src'])
                        if tag.name == 'iframe' and tag.has_attr('src'):
                            extracted_urls_from_html.append(tag['src'])
                        if tag.name == 'link' and tag.has_attr('href'):
                            extracted_urls_from_html.append(tag['href'])

                    # Auch nach URLs in CSS-Styles suchen (rudimentär)
                    style_urls = re.findall(r'url\([\'"]?(.*?)[\'"]?\)', html_body)
                    extracted_urls_from_html.extend(style_urls)

                except Exception as e:
                    print(f"Error parsing HTML part or extracting URLs: {e}")

            # 2. Anhänge extrahieren
            # Prüfe, ob ein Dateiname existiert oder ob Content-Disposition 'attachment' ist
            # ignoriere den Root-Part und Text-Teile, die wir schon verarbeitet haben
            if part.get_filename() or 'attachment' in cdispo:
                # Stelle sicher, dass es sich nicht um den Haupt-Container-Part handelt (multipart-root)
                # und dass es nicht einfach nur ein text/plain oder text/html Teil ist, der keinen Dateinamen hat
                if part.is_multipart() or (not part.get_filename() and 'attachment' not in cdispo):
                    continue  # Überspringe Container-Teile und Text-Teile ohne Dateinamen/explizite Anhangs-Disposition

                # Wenn es ein Anhang ist (hat einen Dateinamen oder ist als Anhang deklariert)
                file_name = part.get_filename()
                if not file_name and 'attachment' in cdispo:  # Versuche Dateiname aus Content-Disposition zu extrahieren
                    fname_match = re.search(r'filename\*?=(.+)', cdispo)
                    if fname_match:
                        file_name = fname_match.group(1).strip()
                        file_name = re.sub(r"[\"']", "", file_name)
                        try:  # RFC 2231 Dekodierung für spezielle Zeichen
                            from email.utils import decode_rfc2231
                            decoded_fn = decode_rfc2231(file_name)
                            if decoded_fn:
                                file_name = decoded_fn
                        except ImportError:
                            pass

                if file_name:  # Wenn ein gültiger Dateiname gefunden wurde
                    file_data = part.get_payload(decode=True)  # Inhalt dekodieren

                    # Sicherstellen, dass das Verzeichnis für Anhänge existiert
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                    full_attachment_dir = os.path.join(script_dir, ATTACHMENT_SAVE_DIR)
                    if not os.path.exists(full_attachment_dir):
                        os.makedirs(full_attachment_dir)

                    # Dateinamen sanitizen (nur Basisteil, keine Pfade, um Path Traversal zu verhindern)
                    sanitized_file_name = os.path.basename(file_name)
                    attachment_path = os.path.join(full_attachment_dir, sanitized_file_name)

                    try:
                        with open(attachment_path, 'wb') as att_file:
                            att_file.write(file_data)

                        attachment_info = {
                            'filename': sanitized_file_name,
                            'size': len(file_data),
                            'path': attachment_path,  # Speichere den vollen Pfad zur Datei
                            'hashes': calculate_file_hashes(attachment_path),
                            'static_analysis': analyze_attachment_static(attachment_path),
                            'virustotal_scan_status': "Skipped (API Key not used/Quota limitations)"  # Platzhalter
                        }
                        analysis_results['Attachments'].append(attachment_info)
                    except Exception as e:
                        print(f"Error saving attachment {sanitized_file_name}: {e}")
                        analysis_results['Attachments'].append({
                            'filename': sanitized_file_name,
                            'error': str(e),
                            'virustotal_scan_status': "Skipped (API Key not used/Quota limitations)"
                        })

        analysis_results['Body_Content'] = email_body[:500] + "..." if len(email_body) > 500 else email_body

        # --- URL-EXTRAKTION & ANALYSE ---
        # URLs aus Klartextbody und HTML-Body kombinieren und Duplikate entfernen
        combined_urls = list(
            set(extract_urls_from_text(email_body) + extracted_urls_from_html))  # NEU: Kombiniere und bereinige
        analysis_results['URLs'] = []

        if combined_urls:
            for url in combined_urls:
                patterns, current_url_score = analyze_url_for_suspicious_patterns(url)

                url_info = {
                    'url': url,
                    'suspicious_patterns': patterns,
                    'url_score': current_url_score,
                    'whois_info': None,  # whois_info wird danach befüllt
                    'virustotal_scan_status': "Skipped (API Key not used/Quota limitations)",  # Placeholder VT
                    'google_safe_Browse_status': check_url_google_safe_Browse(url)  # NEU: GSB-Status
                }

                parsed_domain = urlparse(url).netloc
                if parsed_domain:
                    domain_without_port = parsed_domain.split(':')[0]
                    whois_data = get_whois_info(domain_without_port)
                    if whois_data:
                        url_info['whois_info'] = whois_data
                    else:
                        url_info['whois_info'] = "No WHOIS info found or error"

                url_info['heuristic_verdict'] = get_heuristic_url_verdict(url_info)

                analysis_results['URLs'].append(url_info)
        else:
            analysis_results['URLs'] = "No URLs found in email body."

        return analysis_results

    except FileNotFoundError:
        print(f"Error: The email file '{file_path}' was not found. Please ensure it's in the same directory.")
        return None
    except Exception as e:
        # Importiere traceback, um den vollen Stacktrace auszugeben
        print(f"An unexpected error occurred during analysis: {e}")
        traceback.print_exc()  # Dies gibt den vollständigen Stacktrace aus, sehr hilfreich beim Debuggen
        return None


# --- Hauptteil des Skripts zum Ausführen ---

if __name__ == "__main__":
    # --- Dateiauswahl beim Start ---
    email_file = ""
    while True:
        # Fragen Sie den Benutzer nach dem vollständigen Pfad zur E-Mail-Datei
        # Beispielpfad für Windows: C:\Users\IhrName\PycharmProjects\EmailAnalyzer\beispiel_email.eml
        # Beispielpfad für macOS/Linux: /Users/IhrName/PycharmProjects/EmailAnalyzer/beispiel_email.eml
        input_path = input("\nPlease enter the full path to the .eml file to analyze (e.g., C:\\path\\to\\email.eml): ")

        # Entferne eventuelle Anführungszeichen, die von Drag-and-Drop in manchen Terminals hinzugefügt werden
        input_path = input_path.strip().strip('"')

        if os.path.exists(input_path) and os.path.isfile(input_path):
            email_file = input_path
            break  # Schleife verlassen, wenn ein gültiger Pfad eingegeben wurde
        else:
            print(f"Error: The file '{input_path}' does not exist or is not a valid file. Please try again.")

    # --- Start der Analyse (wie gehabt) ---
    print(f"\n{'=' * 60}")
    print(f"|{'E-Mail Analyse Start':^58}|")
    print(f"|{'Analysiere Datei: ' + os.path.basename(email_file):<58}|")  # Zeigt nur den Dateinamen an
    print(f"{'=' * 60}\n")

    parsed_data = parse_email(email_file)

    if parsed_data:
        print("\n" + "=" * 60)
        print(f"|{'Analyse Ergebnisse':^58}|")
        print("=" * 60)

        # --- 1. HEADER ANALYSE ---
        print("\n--- Header Information ---")
        print(f"{'Visual Sender (user sees in mail):':<35} {parsed_data['Headers'].get('From', 'N/A')}")
        print(f"{'Truth Sender Domain (Return-Path):':<35} {parsed_data['Headers'].get('Return_Path_Domain', 'N/A')}")
        print(f"{'Truth Sender (Actual Originating IP):':<35} {parsed_data['Headers'].get('Origin_IP', 'N/A')}")
        print(
            f"{'Truth Sender Geo-Location:':<35} {parsed_data['Headers'].get('Origin_IP_Geo_Country', 'N/A')}, {parsed_data['Headers'].get('Origin_IP_Geo_City', 'N/A')}")
        print(f"{'Truth Sender ISP:':<35} {parsed_data['Headers'].get('Origin_IP_Geo_ISP', 'N/A')}")
        print(
            f"{'Truth Sender IP Blacklist Status:':<35} {parsed_data['Headers'].get('Origin_IP_Blacklist_Status', 'N/A')}")
        print("-" * 60)
        print(f"{'Recipient (To):':<35} {parsed_data['Headers'].get('To', 'N/A')}")
        print(f"{'Subject:':<35} {parsed_data['Headers'].get('Subject', 'N/A')}")
        print(f"{'Message-ID:':<35} {parsed_data['Headers'].get('Message-ID', 'N/A')}")
        print(f"{'X-Mailer:':<35} {parsed_data['Headers'].get('X-Mailer', 'N/A')}")
        print("-" * 60)
        print(
            f"{'Authentication Results (for From Header Domain):':<35} {parsed_data['Headers'].get('Sender_Domain', 'N/A')}")
        print(f"  {'SPF Result:':<32} {parsed_data['Headers'].get('SPF_Result', 'N/A')}")
        print(f"  {'DKIM Result:':<32} {parsed_data['Headers'].get('DKIM_Result', 'N/A')}")
        print(f"  {'DMARC Result:':<32} {parsed_data['Headers'].get('DMARC_Result', 'N/A')}")
        print("-" * 60)
        spoofing_status = parsed_data['Headers'].get('Spoofing_Detected', False)
        spoofing_message = "YES - LIKELY SPOOFED! (Authentication Failed)" if spoofing_status else "No (Authentication Passed or Policy Missing)"
        print(f"{'!!! SPOOFING DETECTED !!!':<35} {spoofing_message}")
        print("-" * 60)
        print(
            f"{'Suspicious Subject Keywords:':<35} {parsed_data['Headers'].get('Suspicious_Subject_Keywords', 'N/A')}")

        # --- 2. URL ANALYSE ---
        print("\n--- URL Analysis ---")
        if isinstance(parsed_data.get('URLs'), list) and parsed_data['URLs']:
            for i, url_entry in enumerate(parsed_data['URLs']):
                print(f"\n{'=' * 5} URL {i + 1}: {url_entry['url']} {'=' * 5}")
                susp_patterns_str = ', '.join(url_entry['suspicious_patterns']) if url_entry[
                    'suspicious_patterns'] else 'None found'
                print(f"{'  Suspicious Patterns:':<25} {susp_patterns_str}")
                print(f"{'  URL Risk Score:':<25} {url_entry['url_score']}")
                print(f"{'  Heuristic Verdict:':<25} {url_entry.get('heuristic_verdict', 'N/A')}")
                print(f"{'  VirusTotal Status:':<25} {url_entry['virustotal_scan_status']}")
                print(f"{'  Google Safe Browse:':<25} {url_entry.get('google_safe_Browse_status', 'N/A')}")

                if url_entry['whois_info'] and isinstance(url_entry['whois_info'], dict):
                    print("  WHOIS Information:")
                    print(f"    {'Domain Name:':<15} {url_entry['whois_info'].get('domain_name', 'N/A')}")
                    print(f"    {'Registrar:':<15} {url_entry['whois_info'].get('registrar', 'N/A')}")

                    creation_date = url_entry['whois_info'].get('creation_date')
                    if isinstance(creation_date, list):
                        creation_date = ", ".join(map(str, creation_date))
                    print(f"    {'Created:':<15} {creation_date if creation_date else 'N/A'}")

                    expiration_date = url_entry['whois_info'].get('expiration_date')
                    if isinstance(expiration_date, list):
                        expiration_date = ", ".join(map(str, expiration_date))
                    print(f"    {'Expires:':<15} {expiration_date if expiration_date else 'N/A'}")

                    emails = url_entry['whois_info'].get('emails')
                    if isinstance(emails, list):
                        emails = ", ".join(map(str, emails))
                    print(f"    {'Emails:':<15} {emails if emails else 'N/A'}")
                else:
                    print("  WHOIS Information: Not available or error")
                print("=" * 60)

        else:
            print(parsed_data.get('URLs', 'No URLs found.'))

        # --- 3. ATTACHMENT ANALYSIS ---
        print("\n--- Attachment Analysis ---")
        if parsed_data.get('Attachments'):
            # Sicherstellen, dass das Verzeichnis für Anhänge existiert
            if not os.path.exists(ATTACHMENT_SAVE_DIR):
                os.makedirs(ATTACHMENT_SAVE_DIR)
            print(f"Attachments saved to: .\\{ATTACHMENT_SAVE_DIR}\\")  # Zeigt den relativen Pfad an

            for i, att_entry in enumerate(parsed_data['Attachments']):
                print(f"\n{'=' * 5} Attachment {i + 1}: {att_entry.get('filename', 'N/A')} {'=' * 5}")
                if att_entry.get('error'):
                    print(f"  Error processing attachment: {att_entry['error']}")
                else:
                    print(f"  Path: {att_entry.get('path', 'N/A')}")
                    print(f"  Size: {att_entry.get('size', 'N/A')} bytes")
                    print("  Hashes:")
                    print(f"    MD5: {att_entry['hashes'].get('md5', 'N/A')}")
                    print(f"    SHA1: {att_entry['hashes'].get('sha1', 'N/A')}")
                    print(f"    SHA256: {att_entry['hashes'].get('sha256', 'N/A')}")
                    print("  Static Analysis Findings:")
                    for finding in att_entry.get('static_analysis', []):
                        print(f"    - {finding}")
                    print(f"  VirusTotal Scan Status: {att_entry.get('virustotal_scan_status', 'N/A')}")
                print("=" * 60)
        else:
            print("No attachments found.")

        # --- 4. SUMMARY ---
        print("\n" + "=" * 60)
        print(f"|{'Analysis Summary':^58}|")
        print("=" * 60)

        risk_score = 0
        if parsed_data['Headers'].get('Spoofing_Detected'):
            print("Risk Alert: Potential email spoofing detected based on authentication results! (High Risk)")
            risk_score += 3

        if parsed_data['Headers'].get('Origin_IP_Blacklist_Status') not in [
            "Clean (No specific blacklist hit in demo / Public IP)", "N/A",
            "Private IP (Internal Network, Not Publicly Routable)"]:
            print("Risk Alert: Origin IP is blacklisted or suspicious! (Medium Risk)")
            risk_score += 2

        if parsed_data['Headers'].get('Suspicious_Subject_Keywords') != "No suspicious keywords found":
            print(
                f"Risk Alert: Suspicious keywords found in subject: {parsed_data['Headers']['Suspicious_Subject_Keywords']} (Low-Medium Risk)")
            risk_score += 1

        url_total_risk_score = 0
        if isinstance(parsed_data.get('URLs'), list) and parsed_data['URLs']:
            for url_entry in parsed_data['URLs']:
                if url_entry['url_score'] > 0:
                    print(
                        f"Risk Alert: URL '{url_entry['url']}' has a risk score of {url_entry['url_score']} (Patterns: {', '.join(url_entry['suspicious_patterns']) if url_entry['suspicious_patterns'] else 'None found'})")
                    url_total_risk_score += url_entry['url_score']

        if url_total_risk_score > 0:
            risk_score += (url_total_risk_score // 2) + 1

        if parsed_data.get('Attachments'):
            for att_entry in parsed_data['Attachments']:
                if att_entry.get('error'):
                    print(
                        f"Risk Alert: Error processing attachment '{att_entry.get('filename', 'N/A')}': {att_entry['error']} (Medium Risk)")
                    risk_score += 2
                # Hier wird der RISK_SCORE FÜR ANHÄNGE KORRIGIERT
                # Wir suchen in den Static Analysis Findings nach spezifischen Meldungen
                for finding in att_entry.get('static_analysis', []):
                    if "Executable file detected" in finding:
                        print(
                            f"Risk Alert: Attachment '{att_entry.get('filename', 'N/A')}' is an executable file! (CRITICAL RISK)")
                        risk_score += 5  # Sehr hohe Gewichtung
                    elif "Macro-enabled Office document detected" in finding:
                        print(
                            f"Risk Alert: Attachment '{att_entry.get('filename', 'N/A')}' is a macro-enabled Office document! (High Risk)")
                        risk_score += 3
                    elif "Auto-executing macros found" in finding:  # Spezifische Meldung für Auto-Macros
                        print(
                            f"Risk Alert: Attachment '{att_entry.get('filename', 'N/A')}' contains auto-executing macros! (EXTREME RISK)")
                        risk_score += 4  # Etwas höher als nur Makros
                    elif "Potentially suspicious" in finding:  # Andere verdächtige Skripte etc.
                        print(
                            f"Risk Alert: Attachment '{att_entry.get('filename', 'N/A')}' has potentially suspicious static findings. (Medium Risk)")
                        risk_score += 2

        print("\nOverall Risk Assessment:")
        if risk_score == 0:
            print("  --> No obvious risks found in this email. (Based on current analysis)")
        elif risk_score <= 3:
            print("  --> Low to Medium Risk. Some potential indicators found. Please review carefully.")
        elif risk_score <= 7:
            print("  --> Medium to High Risk. Several suspicious indicators found. Proceed with caution!")
        else:
            print(
                "  --> HIGH to CRITICAL Risk! This email is highly suspicious or malicious. Exercise extreme caution!")

        print("\n" + "=" * 60)
        print(f"|{'Analysis Complete':^58}|")
        print("=" * 60 + "\n")

        # --- 5. OPTIONAL: EXPORT RESULTS TO JSON ---
        print("\n" + "=" * 60)
        print(f"|{'Export Results':^58}|")
        print("=" * 60)

        export_choice = input("Do you want to export the analysis results to a JSON file? (y/n): ").lower().strip()
        if export_choice == 'y':
            default_filename_base = os.path.basename(email_file).replace('.eml', '')
            # Sanitize filename for output to prevent invalid characters if the .eml name is weird
            sanitized_default_filename_base = re.sub(r'[^\w\-_\.]', '_', default_filename_base)

            output_json_filename = input(
                f"Enter filename for JSON export (e.g., '{sanitized_default_filename_base}_analysis.json'): ")
            if not output_json_filename:  # Wenn Benutzer nichts eingibt, Standardnamen verwenden
                output_json_filename = f"{sanitized_default_filename_base}_analysis.json"

            # Sicherstellen, dass die Dateiendung .json ist
            if not output_json_filename.lower().endswith('.json'):
                output_json_filename += '.json'

            export_results_to_json(parsed_data, output_json_filename)
        else:
            print("Results not exported to file.")

        # --- 6. EMAIL BODY (OPTIONAL, AM ENDE) ---
        print("\n--- Email Body (Excerpt, max. 500 chars) (For reference only) ---")
        print(parsed_data.get('Body_Content', 'No body content found.'))
        print("-" * 60)


    else:
        print("Email analysis could not be performed successfully.")