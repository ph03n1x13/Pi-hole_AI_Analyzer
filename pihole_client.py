import requests
import logging
import config  # Import our configuration module



"""
- In case you get too many clients/too many seats/429 issue, please read the discussion
https://discourse.pi-hole.net/t/connectivity-auth-api-issues-after-update-to-6-x/78409/3 
"If a script is authenticating again and again, every time it queries the API, it also needs to logout and delete the session every time, to avoid session exhaustion."
Clear unnecessary sessions from 
http://192.168.1.233/admin/settings/api -> Expert ->   Currently active sessions  and remove unnecessary sessions
"""
# Setup basic logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Authentication Function ---

def authenticate() -> str | None:
    """
    Authenticates with the Pi-hole API using the password from config.

    Returns:
        The session ID (sid) string if authentication is successful, otherwise None.
    """
    if not config.PIHOLE_BASE_URL or not config.PIHOLE_PASSWORD:
        logging.error("Pi-hole Base URL or Password not configured in .env file.")
        return None

    auth_url = f"{config.PIHOLE_BASE_URL.rstrip('/')}/api/auth" # Ensure no double slash
    payload = {"password": config.PIHOLE_PASSWORD}
    headers = {'Content-Type': 'application/json'}

    logger.info(f"Attempting authentication with Pi-hole at {auth_url}...")

    try:
        response = requests.post(auth_url, json=payload, headers=headers, timeout=10) # Added timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        auth_data = response.json()

        if auth_data.get("session") and auth_data["session"].get("valid"):
            sid = auth_data["session"].get("sid")
            if sid:
                logger.info("Pi-hole authentication successful.")
                # Optionally log csrf: csrf = auth_data["session"].get("csrf")
                return sid
            else:
                logging.error("Pi-hole authentication successful, but no SID received.")
                return None
        else:
            error_message = auth_data.get("session", {}).get("message", "Unknown authentication error")
            logging.error(f"Pi-hole authentication failed: {error_message}")
            return None

    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection Error connecting to Pi-hole: {e}")
        return None
    except requests.exceptions.Timeout:
        logging.error(f"Timeout connecting to Pi-hole at {auth_url}.")
        return None
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP Error during Pi-hole authentication: {e.response.status_code} - {e.response.text}")
        return None
    except requests.exceptions.JSONDecodeError:
        logging.error("Failed to decode JSON response from Pi-hole authentication.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during Pi-hole authentication: {e}", exc_info=True) # Log stack trace
        return None


# --- Query Fetching Function ---

def get_recent_queries(sid: str) -> list[dict] | None:
    """
    Fetches recent DNS queries from the Pi-hole API using the session ID.

    Args:
        sid: The valid session ID obtained from authenticate().

    Returns:
        A list of dictionaries, 100 for now, where each dictionary represents a processed
        DNS query, or None if an error occurs. Returns an empty list if
        no queries are found but the request was successful.
    """
    if not sid:
        logging.error("Cannot fetch queries: Invalid or missing session ID (sid).")
        return None
    if not config.PIHOLE_BASE_URL:
        logging.error("Pi-hole Base URL not configured in .env file.")
        return None

    queries_url = f"{config.PIHOLE_BASE_URL.rstrip('/')}/api/queries"
    # Pi-hole API expects the session ID as a cookie
    headers = {'sid': sid}

    logger.info(f"Fetching recent queries from {queries_url} ...")

    try:
        # Note: The 'api/queries' endpoint might return *all* queries or a large number.
        # There isn't a standard, documented way in the base API to ask for only
        # queries since a specific time via simple parameters. We fetch the default
        # set and can filter later if needed.
        # Consider adding query parameters if your Pi-hole version supports them,
        # e.g., params={'limit': 1000} or similar, but check documentation.
        response = requests.get(queries_url, headers=headers, timeout=30, verify=False) # Longer timeout for potentially large data
        response.raise_for_status()

        query_data = response.json()

        if not isinstance(query_data, dict):
             # Handle potential errors where the API might return a dict on auth failure
             if isinstance(query_data, dict) and query_data.get("error"):
                 logging.error(f"Pi-hole API returned an error: {query_data['error']}")
                 return None
             else:
                 logging.error(f"Unexpected data format received from Pi-hole queries endpoint: Expected list, got {type(query_data)}")
                 return None

        processed_queries = []
        # Check the length
        logger.info(f"Received {len(query_data['queries'])} raw query entries from Pi-hole.")

        # Process each query to extract only the needed fields
        for query in query_data["queries"]:
            # Basic validation to ensure keys exist, using .get() with defaults
            client_info = query.get("client", {})
            processed_query = {
                "id": query.get("id"), # Useful for tracking/debugging
                "timestamp": query.get("time"), # Unix timestamp (float)
                "type": query.get("type"), # e.g., A, AAAA, CNAME
                "status": query.get("status"), # e.g., GRAVITY, FORWARDED, CACHE
                "domain": query.get("domain"),
                "client_ip": client_info.get("ip"),
                "client_name": client_info.get("name"), # Can be None
                "upstream": query.get("upstream"), # Where the query was sent if forwarded
                # Add 'list_id' if you want to know which blocklist it hit (if status is GRAVITY)
                "list_id": query.get("list_id") if query.get("status") == "GRAVITY" else None
            }
            # Optional: Skip entries with missing essential fields like domain or timestamp?
            if processed_query["domain"] and processed_query["timestamp"]:
                 processed_queries.append(processed_query)
            else:
                 logging.warning(f"Skipping query due to missing domain or timestamp: {query}")


        logger.info(f"Successfully processed {len(processed_queries)} queries.")
        return processed_queries

    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection Error fetching queries from Pi-hole: {e}")
        return None
    except requests.exceptions.Timeout:
        logging.error(f"Timeout fetching queries from Pi-hole at {queries_url}.")
        return None
    except requests.exceptions.HTTPError as e:
        # Check specifically for 401/403 which might indicate expired/invalid sid
        if e.response.status_code in [401, 403]:
             logging.error(f"HTTP Error {e.response.status_code} fetching queries: Authentication failed or session expired. Try re-authenticating.")
        else:
             logging.error(f"HTTP Error fetching queries from Pi-hole: {e.response.status_code} - {e.response.text}")
        return None
    except requests.exceptions.JSONDecodeError:
        logging.error("Failed to decode JSON response from Pi-hole queries endpoint.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred fetching Pi-hole queries: {e}", exc_info=True)
        return None


def delete_session(sid) -> None:
    logger.info("Deleting Session...")
    auth_url = f"{config.PIHOLE_BASE_URL.rstrip('/')}/api/auth" # Ensure no double slash
    headers = {'sid': sid}
    try:
        response = requests.delete(auth_url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection Error deleting session to Pi-hole: {e}")
        return None
    except requests.exceptions.Timeout:
        logging.error(f"Timeout deleting session to Pi-hole at {auth_url}.")
        return None
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP Error during Pi-hole session delete: {e.response.status_code} - {e.response.text}")
        return None
    except requests.exceptions.JSONDecodeError:
        logging.error("Failed to decode JSON response from Pi-hole session delete.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during Pi-hole session delte: {e}", exc_info=True) # Log stack trace