import time
import logging
from datetime import datetime
import sys # To exit cleanly

# Import our custom modules
import config
import pihole_client
import ai_analyzer
import storage_manager
import notification_manager

# --- Configuration for Logging ---
# Configure logging level, format, and output (e.g., file and console)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def configure_logging():
    # Root logger
    logger  = logging.getLogger()
    formatter = logging.Formatter(
       fmt='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(message)s',
       datefmt="%Y-%m-%d %H:%M:%S"
   )
   # Create and configure stream handler (stdout)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    # Create and configure file handler
    file_handler = logging.FileHandler("analyzer.log", mode='a')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    # Attach handlers to the logger
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)


# --- Constants and State ---
# Optional: Use a file to keep track of the last processed timestamp
# This avoids re-analyzing the same old queries repeatedly.
LAST_CHECK_TIMESTAMP_FILE = "last_check.txt"

# Define which AI categories trigger a notification
# Customize this list based on your alerting preferences
NOTIFY_CATEGORIES = {"Malicious", "Illegal", "AdultContent", "Gambling", "Suspicious"} # Example: Notify on these


# --- Helper Functions ---
def load_last_check_timestamp() -> float:
    """Loads the timestamp of the last successfully processed query."""
    try:
        with open(LAST_CHECK_TIMESTAMP_FILE, 'r') as f:
            timestamp_str = f.read().strip()
            logger.info(f"Loaded last check timestamp: {timestamp_str}")
            return float(timestamp_str)
    except FileNotFoundError:
        logger.info("Last check timestamp file not found. Processing all available recent queries.")
        return 0.0 # Start from the beginning if file doesn't exist
    except ValueError:
        logger.error(f"Invalid timestamp format in {LAST_CHECK_TIMESTAMP_FILE}. Starting from beginning.")
        return 0.0
    except Exception as e:
        logger.error(f"Error loading last check timestamp: {e}")
        return 0.0 # Default to safety

def save_last_check_timestamp(timestamp: float):
    """Saves the timestamp of the latest processed query."""
    try:
        with open(LAST_CHECK_TIMESTAMP_FILE, 'w') as f:
            f.write(str(timestamp))
        logger.info(f"Saved last check timestamp: {timestamp}")
    except Exception as e:
        logger.error(f"Error saving last check timestamp: {e}")


# --- Main Execution Logic ---

def run_analysis_cycle():
    """Performs one full cycle of fetching, analyzing, storing, and notifying."""
    logger.info("Starting new analysis cycle...")
    findings_for_notification = [] # Collect findings that trigger alerts
    latest_processed_query_time = 0.0

    # 1. Initialize Database (ensure table exists)
    #    Do this early so we can store errors if needed.
    storage_manager.initialize_database()

    # 2. Authenticate with Pi-hole
    sid = pihole_client.authenticate()
    if not sid:
        logger.error("Pi-hole authentication failed. Cannot proceed this cycle.")
        return # Stop this cycle if auth fails

    # 3. Load Last Check Timestamp
    last_check_time = load_last_check_timestamp()

    # 4. Fetch Recent Queries
    #    Note: Pi-hole API might not support filtering by time directly.
    #    We fetch a recent batch and filter locally.
    raw_queries = pihole_client.get_recent_queries(sid)
    if raw_queries is None: # Check for None specifically (indicates error)
        logger.error("Failed to retrieve queries from Pi-hole. Skipping rest of cycle.")
        return
    elif not raw_queries: # Empty list is okay, just means no queries
        logger.info("No recent queries returned by Pi-hole API.")
        # Optionally update timestamp file even if no queries, to mark the check time?
        # save_last_check_timestamp(time.time()) # Or keep the old one? Your choice.
        logger.info("Analysis cycle finished: No new queries.")
        return

    # 5. Filter Queries Newer Than Last Check
    new_queries = [
        q for q in raw_queries
        if q.get("timestamp") and q["timestamp"] > last_check_time
    ]

    if not new_queries:
        logger.info(f"No new queries found since last check time ({datetime.fromtimestamp(last_check_time).isoformat()}).")
        # Update timestamp to the latest query time seen, even if none are 'new' for processing
        latest_query_time_in_batch = max(q['timestamp'] for q in raw_queries if q.get("timestamp")) if raw_queries else last_check_time
        save_last_check_timestamp(max(last_check_time, latest_query_time_in_batch))
        logger.info("Analysis cycle finished: No new queries to process.")
        return

    logger.info(f"Processing {len(new_queries)} new queries since last check...")
    # Track the latest timestamp among the queries we are actually processing
    latest_processed_query_time = max(q['timestamp'] for q in new_queries if q.get("timestamp"))


    # 6. Extract Unique Domains from New Queries
    #    Create a mapping: domain -> list of associated query details (timestamp, client)
    domain_query_map = {}
    for query in new_queries:
        domain = query.get("domain")
        if domain:
            if domain not in domain_query_map:
                domain_query_map[domain] = []
            domain_query_map[domain].append({
                "timestamp": query.get("timestamp"),
                "client_ip": query.get("client_ip")
            })

    unique_domains_to_check = list(domain_query_map.keys())
    logger.info(f"Found {len(unique_domains_to_check)} unique new domains to analyze.")


    # 7. (Optional) Pre-check with Urlhaus: This will be added later


    # 8. Analyze with AI (Gemini)
    #    We'll send all unique *new* domains, regardless of GSB findings,
    #    as the AI provides richer category analysis (e.g., Gambling, Adult).
    ai_analysis_results = None
    if unique_domains_to_check: # Only call AI if there are domains
        logger.info("Running AI analysis...")
        try:
            # Pass the list of unique domains directly to the analyzer
            # The analyzer internally handles creating the prompt with these domains
            # Construct mock query list just containing unique domains for simplicity? No, ai_analyzer expects full query dicts to potentially use more context later. Pass original new_queries?
            # Let's stick to sending only unique domains to the AI analyzer for now for prompt simplicity.
            # We will need to adjust ai_analyzer or prompt if we want it to use the full query context.
            # Let's REVISE ai_analyzer to accept just a list of domains? OR create a helper here.

            # --- OPTION A: Send only unique domains to AI ---
            # Create a simple list of dicts just for the AI call, containing only domains.
            # This requires ai_analyzer to be flexible or we adjust it. Let's assume ai_analyzer uses the domain primarily.
            # temp_list_for_ai = [{"domain": d} for d in unique_domains_to_check] # Minimal list
            # ai_analysis_results = ai_analyzer.analyze_dns_batch(temp_list_for_ai)

            # --- OPTION B: Send original queries containing unique domains ---
            # Filter original queries to only include those with the unique domains we care about
            # This preserves original context if ai_analyzer uses it. More data sent.
            queries_for_ai = [q for q in new_queries if q.get("domain") in unique_domains_to_check]
            # Consider batching if queries_for_ai is huge (thousands). Gemini has input token limits.
            # Example batching (conceptual):
            # BATCH_SIZE_AI = 500 # Adjust based on typical query size and token limits
            # all_ai_results_list = []
            # for i in range(0, len(queries_for_ai), BATCH_SIZE_AI):
            #    batch_queries = queries_for_ai[i:i + BATCH_SIZE_AI]
            #    batch_results = ai_analyzer.analyze_dns_batch(batch_queries) # ai_analyzer needs to process its input and return domain-based analysis
            #    if batch_results:
            #        all_ai_results_list.extend(batch_results)
            #    time.sleep(2) # Pause between large batches
            # ai_analysis_results = all_ai_results_list # Combine results

            # Let's assume one batch for now unless we hit limits:
            ai_analysis_results = ai_analyzer.analyze_dns_batch(queries_for_ai) # Send relevant subset of original queries

        except Exception as e:
            logger.error(f"Error during AI analysis: {e}", exc_info=True)
        logger.info("AI analysis complete.")
    else:
        logger.info("No unique new domains to send for AI analysis.")


    # 9. Process Findings and Store in Database
    logger.info("Processing and storing findings...")
    processed_domains = set() # Keep track of domains already processed to avoid duplicates if AI and GSB overlap significantly

    # Process AI analysis results
    if ai_analysis_results:
        ai_findings_map = {item['domain']: item for item in ai_analysis_results if item.get('domain')} # Map for easy lookup

        for domain, query_details_list in domain_query_map.items():
            if domain in ai_findings_map and domain not in processed_domains: # Check if AI found something and GSB didn't already cover it
                ai_result = ai_findings_map[domain]
                ai_categories = ai_result.get('categories', [])
                ai_reason = ai_result.get('reason', 'AI analysis result.')

                if ai_categories: # Only store if AI assigned a category
                    # Again, store one representative finding per domain for this batch
                    first_query_time = query_details_list[0]['timestamp']
                    first_client_ip = query_details_list[0]['client_ip']
                    joined_categories = ", ".join(ai_categories)

                    success = storage_manager.save_finding(
                        query_timestamp=first_query_time,
                        client_ip=first_client_ip,
                        domain=domain,
                        category=joined_categories,
                        reason=ai_reason,
                        source="AI"
                    )
                    if success:
                        # Check if any of the assigned AI categories trigger notification
                        if any(cat in NOTIFY_CATEGORIES for cat in ai_categories):
                             findings_for_notification.append({
                                  "timestamp": first_query_time,
                                  "client_ip": first_client_ip,
                                  "domain": domain,
                                  "category": joined_categories,
                                  "reason": ai_reason,
                                  "source": "AI"
                             })
                    processed_domains.add(domain) # Mark as processed


    logger.info("Processing and storing findings complete.")


    # 10. Send Notifications (if any findings warrant it)
    if findings_for_notification:
        logger.info(f"Found {len(findings_for_notification)} findings triggering notification.")
        subject = f"Pi-hole Alert: {len(findings_for_notification)} Noteworthy DNS Queries Detected"
        body_lines = ["Pi-hole AI Analyzer detected the following noteworthy DNS queries:\n"]
        for finding in findings_for_notification:
            ts = datetime.fromtimestamp(finding['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            body_lines.append(
                f"- Time: {ts}\n"
                f"  Client: {finding['client_ip'] or 'Unknown'}\n"
                f"  Domain: {finding['domain']}\n"
                f"  Category: {finding['category']}\n"
                f"  Source: {finding['source']}\n"
                f"  Reason: {finding['reason'] or 'N/A'}\n"
            )
        body = "\n".join(body_lines)

        email_success = notification_manager.send_notification_email(subject, body)
        if email_success:
            logger.info("Notification email sent successfully.")
        else:
            logger.error("Failed to send notification email.")
    else:
        logger.info("No findings triggered a notification in this cycle.")


    # 11. Update Last Check Timestamp
    if latest_processed_query_time > 0.0:
        save_last_check_timestamp(latest_processed_query_time)
    elif raw_queries: # If we fetched queries but none were new, update to latest time seen
         latest_query_time_in_batch = max(q['timestamp'] for q in raw_queries if q.get("timestamp"))
         save_last_check_timestamp(max(last_check_time, latest_query_time_in_batch))


    logger.info("Analysis cycle finished.")


# --- Main Execution Loop ---
if __name__ == "__main__":
    configure_logging()
    # --- Initial Checks ---
    # Check if essential Pi-hole config is present before starting loop
    if not config.PIHOLE_BASE_URL or not config.PIHOLE_PASSWORD:
         logging.critical("Essential Pi-hole configuration (URL or Password) missing in .env. Exiting.")
         sys.exit(1) # Exit with an error code

    # Check AI key if AI analysis is considered essential
    if not config.GOOGLE_API_KEY:
        logging.warning("Google AI API Key (GOOGLE_API_KEY) is missing. AI analysis will be skipped.")
        # Decide if this is critical or not. If critical, uncomment the next lines:
        # logging.critical("Google AI API Key is required for core functionality. Exiting.")
        # sys.exit(1)

    # Check email config if notifications are essential
    # ... add similar checks for required email config if notifications MUST work ...


    # --- Run Cycle ---
    # For a single run:
    run_analysis_cycle()

    logger.info("--- Pi-hole AI Analyzer Finished ---")