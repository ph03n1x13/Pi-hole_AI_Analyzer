import os
from dotenv import load_dotenv
import logging

# Load environment variables from .env file
# Searches for the .env file starting from the current directory up the tree
load_dotenv()

# --- Pi-hole Configuration ---
PIHOLE_BASE_URL = os.getenv("PIHOLE_BASE_URL")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD")

# --- Google AI (Gemini) Configuration ---
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# --- Google Safe Browsing Configuration ---
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
SAFE_BROWSING_CLIENT_ID = os.getenv("SAFE_BROWSING_CLIENT_ID", "pihole-ai-analyzer") # Default if not set
SAFE_BROWSING_CLIENT_VERSION = os.getenv("SAFE_BROWSING_CLIENT_VERSION", "1.0.0") # Default if not set

# --- Database Configuration ---
DATABASE_PATH = os.getenv("DATABASE_PATH", "./findings.db") # Default path if not set

# --- Email Notification Configuration ---
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT_STR = os.getenv("SMTP_PORT")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_SENDER = os.getenv("EMAIL_SENDER", SMTP_USERNAME) # Default sender to username if not specified
EMAIL_RECIPIENT = os.getenv("EMAIL_RECIPIENT")

# --- Basic Validation and Type Conversion ---
# Convert SMTP port to integer, handle potential error
SMTP_PORT = None
if SMTP_PORT_STR:
    try:
        SMTP_PORT = int(SMTP_PORT_STR)
    except ValueError:
        logging.error(f"Invalid SMTP_PORT value in .env file: '{SMTP_PORT_STR}'. Must be an integer.")
        # Decide how to handle: exit, use a default, or let it be None and handle later
        # For now, we'll let it be None, and the email function should check for it.

# Check for essential missing variables (optional but recommended)
REQUIRED_VARS = {
    "PIHOLE_BASE_URL": PIHOLE_BASE_URL,
    "PIHOLE_PASSWORD": PIHOLE_PASSWORD,
    "GOOGLE_API_KEY": GOOGLE_API_KEY,
    # Add others as needed, e.g., SMTP settings if email is critical
}

missing_vars = [name for name, value in REQUIRED_VARS.items() if not value]

if missing_vars:
    logging.error(f"Missing required environment variables in .env file: {', '.join(missing_vars)}")
    # Consider raising an exception or exiting if these are absolutely critical
    # raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")


# --- Log Loaded Configuration (Optional, Be Careful with Secrets!) ---
# Avoid logging passwords or full API keys in production environments
# logging.basicConfig(level=logging.INFO) # Configure logging level if needed elsewhere
# logging.info("Configuration loaded:")
# logging.info(f"  PIHOLE_BASE_URL: {PIHOLE_BASE_URL}")
# logging.info(f"  GOOGLE_API_KEY loaded: {'Yes' if GOOGLE_API_KEY else 'No'}")
# logging.info(f"  SAFE_BROWSING_API_KEY loaded: {'Yes' if SAFE_BROWSING_API_KEY else 'No'}")
# logging.info(f"  DATABASE_PATH: {DATABASE_PATH}")
# logging.info(f"  SMTP_SERVER: {SMTP_SERVER}")
# logging.info(f"  SMTP_PORT: {SMTP_PORT}")
# logging.info(f"  SMTP_USERNAME: {SMTP_USERNAME}")
# logging.info(f"  EMAIL_RECIPIENT: {EMAIL_RECIPIENT}")