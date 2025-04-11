# storage_manager.py

import sqlite3
import logging
import config # Import configuration (for DATABASE_PATH)
import time
import os

# Setup basic logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Constants ---
DB_FILE = config.DATABASE_PATH
TABLE_NAME = "findings"

# --- Database Initialization ---

def initialize_database():
    """
    Initializes the SQLite database and the 'findings' table if they don't exist.
    """
    # Ensure the directory for the database file exists
    db_dir = os.path.dirname(DB_FILE)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir)
            logger.info(f"Created database directory: {db_dir}")
        except OSError as e:
            logger.error(f"Failed to create database directory {db_dir}: {e}")
            return # Cannot proceed if directory creation fails

    try:
        # Connect to the database file. Creates the file if it doesn't exist.
        conn = sqlite3.connect(DB_FILE, timeout=10) # Added timeout
        cursor = conn.cursor()

        # Create table if it doesn't exist
        # Using REAL for timestamps (supports fractional seconds from time.time())
        # Using TEXT for IP, domain, category, reason, source
        cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_timestamp REAL NOT NULL,
            detection_timestamp REAL NOT NULL,
            client_ip TEXT,
            domain TEXT NOT NULL,
            category TEXT NOT NULL,
            reason TEXT,
            source TEXT NOT NULL CHECK(source IN ('AI', 'SafeBrowsing'))
        )
        """)

        # Optional: Add indexes for faster lookups if needed later
        cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_domain ON {TABLE_NAME}(domain)")
        cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_timestamp ON {TABLE_NAME}(detection_timestamp)")
        cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_category ON {TABLE_NAME}(category)")

        conn.commit() # Save the changes (table creation/indexing)
        logger.info(f"Database '{DB_FILE}' initialized successfully. Table '{TABLE_NAME}' is ready.")

    except sqlite3.Error as e:
        logger.error(f"Database error during initialization: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"An unexpected error occurred during database initialization: {e}", exc_info=True)
    finally:
        if conn:
            conn.close() # Always close the connection


# --- Saving Findings ---

def save_finding(query_timestamp: float, client_ip: str | None, domain: str, category: str, reason: str | None, source: str):
    """
    Saves a single analysis finding to the database.

    Args:
        query_timestamp: The Unix timestamp (float) from the original DNS query.
        client_ip: The IP address of the client making the query (can be None).
        domain: The domain name identified.
        category: The category assigned (e.g., "Malicious", "AdultContent").
        reason: The explanation for the categorization (can be None).
        source: The source of the finding ("AI" or "SafeBrowsing").

    Returns:
        bool: True if saving was successful, False otherwise.
    """
    if not DB_FILE:
         logger.error("Database path not configured. Cannot save finding.")
         return False

    detection_timestamp = time.time() # Record when the script detected this

    # Basic validation
    if not all([query_timestamp, domain, category, source]):
        logging.warning(f"Attempted to save finding with missing essential data: domain='{domain}', category='{category}', source='{source}'")
        return False
    if source not in ('AI', 'SafeBrowsing'):
         logging.warning(f"Invalid source '{source}' provided for finding. Must be 'AI' or 'SafeBrowsing'.")
         return False

    conn = None # Initialize conn to None
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        cursor = conn.cursor()

        cursor.execute(f"""
        INSERT INTO {TABLE_NAME} (
            query_timestamp, detection_timestamp, client_ip, domain,
            category, reason, source
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            query_timestamp,
            detection_timestamp,
            client_ip, # Will be stored as NULL if None
            domain,
            category,
            reason, # Will be stored as NULL if None
            source
        ))

        conn.commit()
        logging.debug(f"Successfully saved finding: {source} - {category} - {domain}")
        return True

    except sqlite3.IntegrityError as e:
         # This could happen if constraints are violated (e.g., NOT NULL, CHECK)
         logger.error(f"Database integrity error saving finding for '{domain}': {e}", exc_info=True)
         return False
    except sqlite3.OperationalError as e:
         # Could indicate issues like "database is locked" if concurrency happens
         logger.error(f"Database operational error saving finding for '{domain}': {e}", exc_info=True)
         # Optional: Implement retry logic here for lock errors
         return False
    except sqlite3.Error as e:
        logger.error(f"Database error saving finding for '{domain}': {e}", exc_info=True)
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred saving finding: {e}", exc_info=True)
        return False
    finally:
        if conn:
            conn.close()