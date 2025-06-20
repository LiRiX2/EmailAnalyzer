# Email Analyzer

A comprehensive Python script designed to assist in the analysis of suspicious email messages. This tool parses email headers, extracts and evaluates URLs, identifies and analyzes attachments, and provides a consolidated risk assessment to help in the detection of phishing, malware, and spoofing attempts.

## ✨ Features

* **Interactive File Selection:** Easily select any `.eml` file for analysis at runtime.
* **Detailed Header Analysis:**
    * Extracts critical headers (From, To, Subject, Message-ID, X-Mailer).
    * Clearly distinguishes between **Visual Sender** (what the user sees) and **Truth Sender** (actual originating IP and Return-Path domain).
    * Displays SPF, DKIM, and DMARC authentication results.
    * Prominent **Spoofing Detection** based on authentication failures.
* **IP Geolocation & Blacklist Check:** Provides geographical information and a basic blacklist status for the originating IP address.
* **Subject Keyword Detection:** Identifies suspicious keywords in the email subject line.
* **Advanced URL Analysis:**
    * Extracts URLs from both plain text and **HTML email bodies**.
    * Identifies obscured or hidden URLs within HTML elements (`<a>` with deceptive text, `<img>`, `<iframe>`, CSS `url()`).
    * Applies **heuristic scoring and verdicts** based on patterns (e.g., IP addresses as domain, long query parameters, suspicious keywords in path/query).
    * Retrieves WHOIS information for extracted domains (creation date, registrar, contact emails).
    * Includes placeholders for integration with external APIs like VirusTotal and Google Safe Browse (API keys not used in this public version).
* **Attachment Analysis:**
    * Extracts and securely saves attachments to a local directory (`attachments_extracted/`).
    * Calculates MD5, SHA1, and SHA256 hashes for each attachment.
    * Performs **static analysis** to detect executable files, script files, and **VBA macros in Office documents (using `oletools`)**. Detects auto-executing macros.
    * Includes placeholders for VirusTotal file hash lookups.
* **Consolidated Risk Assessment:** Provides an overall risk score and verdict based on all detected indicators.
* **Structured JSON Export:** Option to export the full analysis results into a well-formatted JSON file for archiving or further processing.
* **Clear Console Output:** Designed for readability and quick identification of critical information.

## 🚀 Getting Started

### Prerequisites

* Python 3.x installed on your system.
* `pip` (Python package installer) for dependency management.

### Installation

1.  **Clone the repository** (or download the ZIP and extract it) to your local machine:
    ```bash
    git clone [https://github.com/YourGitHubUsername/EmailAnalyzer.git](https://github.com/YourGitHubUsername/EmailAnalyzer.git)
    cd EmailAnalyzer
    ```
    *(Replace `YourGitHubUsername` with your actual GitHub username)*

2.  **Install the required Python libraries:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You'll need to create `requirements.txt` as described below)*

### Creating `requirements.txt`

In the root directory of your project (where `email_analyzer.py` is), create a file named `requirements.txt` and add the following lines:
requests
python-whois
beautifulsoup4
python-dateutil
oletools

### Usage

1.  **Run the script:**
    ```bash
    python email_analyzer.py
    ```

2.  **Follow the prompts:**
    The script will ask you to enter the full path to the `.eml` file you want to analyze.
    * **Example (Windows):** `C:\Users\YourUser\Desktop\suspicious_email.eml`
    * **Example (macOS/Linux):** `/home/youruser/emails/suspicious_email.eml`
    * *(You can often drag and drop the `.eml` file into the terminal window to get its path.)*

3.  **Review the analysis:** The results will be displayed in your console.
4.  **Export to JSON:** After the analysis, you'll be prompted if you wish to export the full results to a JSON file.

### 🧪 Testing

To test the full capabilities of the analyzer, you can create sample `.eml` files:

* **Download an original email:** Most email clients allow you to "Show Original" or "Download Original" of an email, saving it as a `.eml` file.
* **Craft a test email:**
    * **For HTML analysis:** Send yourself an email via Gmail/Outlook.com with deliberately crafted HTML links (e.g., `<a>` tags where the displayed text differs from the actual `href` URL, or `<img>` tags with suspicious `src`). Then download its original `.eml`.
    * **For attachment analysis:** Attach a dummy `test.txt`, a renamed `dummy.exe` (a text file renamed to `.exe`), and a macro-enabled Office document (`.docm` or `.xlsm`) containing a safe test macro (e.g., a simple `MsgBox` in `Sub AutoOpen()` or `Sub Workbook_Open()`). Send it to yourself and download the original `.eml`.

### 💡 Future Enhancements

* **API Key Integration:** Implement actual calls to VirusTotal and Google Safe Browse APIs (requires obtaining API keys and managing quotas).
* **Advanced HTML Parsing:** Deeper analysis of JavaScript obfuscation and CSS-based phishing techniques.
* **Batch Processing:** Add functionality to analyze multiple `.eml` files within a directory.
* **GUI (Graphical User Interface):** Develop a simple desktop UI for easier interaction.

## ✍️ Author

* **Tobias Kastenhuber / LiRiX2**

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details (you can create this file separately on GitHub or in your project root).

---
