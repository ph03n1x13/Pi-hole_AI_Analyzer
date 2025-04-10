# Pi-hole AI Analyzer
![analyzer image](assets/analyzer.jpg "Title")    


[![Python Version](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Google Gemini API](https://img.shields.io/badge/Google%20AI-Gemini%20API-orange.svg)](https://ai.google.dev/)
[![Integration](https://img.shields.io/badge/Integration-Pi--hole-lightgrey.svg)](https://pi-hole.net/)
[![Status](https://img.shields.io/badge/Status-Beta-green.svg)]()

**Note: This is an experimental project. All the codes are generated using Google AI Studio. 
The author and maintainer of this repository tests and supervise the business logic as well as code optimisation**

Analyze DNS queries logged by your Pi-hole utilising Google's Gemini AI and Threat Intelligence! 
This script automatically fetches recent DNS requests, analyzes them for potential malicious activity, unwanted content categories (like adult, gambling, dating), and suspicious patterns, stores the findings, and notifies you via email.

## Key Features 🚀

*   **Pi-hole Integration:** Fetches DNS query logs directly from your Pi-hole instance's API.
*   **Threat Intelligence:** Optionally checks domains against URLhaus (Malware, Phishing, Unwanted Software). **[To be implemented]**
*   **AI-Powered Analysis:** Leverages the Google Gemini API to analyze domains for:
    *   Malicious activity (Malware C&C, Phishing)
    *   Adult/Explicit Content
    *   Gambling Sites
    *   Dating Sites/Apps
    *   Potentially Illegal Content Sites
    *   Suspicious activity (Trackers, Adware, unusual TLDs)
*   **Persistent Storage:** Saves detected findings (timestamp, client IP, domain, category, reason, source) to a local SQLite database (`findings.db`) for historical review.
*   **Email Notifications:** Sends configurable email alerts when specific categories of findings are detected.
*   **State Management:** Keeps track of the last processed query timestamp to avoid redundant analysis.
*   **Configurable:** Easily configure API keys, Pi-hole data fetching, database path, and email settings via a `.env` file.
*   **Modular Code:** Structured codebase for easier maintenance and extension.

## How It Works ⚙️

The `main.py` script orchestrates the following workflow:

1.  **Authenticate:** Connects to the Pi-hole API using credentials from `.env`.
2.  **Load State:** Reads the timestamp of the last processed query.
3.  **Fetch Queries:** Retrieves recent DNS query logs from Pi-hole.
4.  **Filter New:** Selects only queries that occurred after the last processed timestamp.
5.  **Extract Unique Domains:** Identifies unique domains from the new queries.
6.  **(Optional) URLhaus Check:** Matches unique domains against URLhaus for known threats.
7.  **AI Analysis:** Sends the unique domains (within their query context) to the Google Gemini API for categorization based on the defined criteria (Malicious, Adult, Gambling, etc.).
8.  **Store Findings:** Records findings from both Safe Browsing and AI analysis into the SQLite database (`findings.db`), including details like the original query time and client IP.
9.  **Notify:** If findings match predefined alert categories (e.g., "Malicious", "AdultContent"), compiles a summary and sends an email notification.
10. **Save State:** Updates the last processed query timestamp.

This cycle is designed to be run periodically (e.g., every 5-15 minutes) using a scheduler like `cron` or `systemd`.

## Tech Stack 🛠️

*   **Language:** Python 3.9+
*   **Core Libraries:**
    *   `requests`: For HTTP API interactions (Pi-hole, Safe Browsing)
    *   `google-generativeai`: Official Google AI Python SDK for Gemini
    *   `python-dotenv`: For managing environment variables (`.env` file)
    *   `sqlite3`: Built-in Python library for database storage
    *   `smtplib`, `email.mime`: Built-in Python libraries for sending email
    *   `pytest`: For unit testing modules
*   **APIs:**
    *   Pi-hole API
    *   Google AI Gemini API
*   **Database:** SQLite

## Setup & Installation 📋

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your_username/pihole-ai-analyzer.git # Replace with your repo URL
    cd pihole-ai-analyzer
    ```

2.  **Create & Activate Virtual Environment:**
    ```bash
    python3 -m venv venv # Or your preferred environment name
    source venv/bin/activate
    # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Obtain API Keys:**
    *   **Google AI (Gemini):** Go to [Google AI Studio](https://aistudio.google.com/) or Google Cloud Console to create an API key.

5.  **Configure Environment:**
    *   Copy the example environment file:
        ```bash
        cp .env.example .env
        ```
    *   Edit the `.env` file and fill in **all** required values (Pi-hole URL/Password, Google API keys, SMTP server details, recipient email, etc.). See the next section for details.
    *   **Security:** Ensure the `.env` file is added to your `.gitignore` file (it should be by default if you cloned this repo with the provided `.gitignore`) to avoid committing secrets.

## Configuration (`.env` File) 🔑

The `.env` file stores all necessary configurations and secrets. Make sure to replace placeholder values with your actual details.

```dotenv
# .env - Configuration for Pi-hole AI Analyzer

# --- Pi-hole Configuration ---
PIHOLE_BASE_URL=http://YOUR_PIHOLE_IP_OR_HOSTNAME/admin/api/ # e.g., http://192.168.1.5/admin/api/
PIHOLE_PASSWORD=YOUR_PIHOLE_WEB_PASSWORD

# --- Google AI (Gemini) Configuration ---
GOOGLE_API_KEY=YOUR_GEMINI_API_KEY

# --- Google Safe Browsing Configuration (Optional but Recommended) ---
SAFE_BROWSING_API_KEY=YOUR_SAFE_BROWSING_API_KEY
SAFE_BROWSING_CLIENT_ID="pihole-ai-analyzer" # Your app name
SAFE_BROWSING_CLIENT_VERSION="1.0.0"      # Your app version

# --- Database Configuration ---
DATABASE_PATH=./findings.db # Path to the SQLite database file

# --- Email Notification Configuration ---
SMTP_SERVER=smtp.example.com          # e.g., smtp.gmail.com
SMTP_PORT=587                         # e.g., 587 (TLS) or 465 (SSL)
SMTP_USERNAME=your_email@example.com  # Your login username for SMTP
SMTP_PASSWORD=YOUR_APP_PASSWORD_OR_REGULAR_PASSWORD # *** USE APP PASSWORD IF POSSIBLE (e.g., Gmail 2FA) ***
EMAIL_SENDER=your_sending_email@example.com # Email 'From' address (often same as username)
EMAIL_RECIPIENT=recipient_email@example.com # Where to send alerts
```
## To Dos
**Please note that this is a PoC phase codebase and the development is still going on**
- Optimize AI Prompt 
- Add URLhaus feature 
- Fix analyzer.log empty issue 
- Add unit tests in a separate `tests/` folder. Presently test codes are written in respective modules.