import json
import time
import config  # Import our configuration module
import logging
import google.generativeai as genai

# Setup basic logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- AI Configuration ---
# Configure the Generative AI client
try:
    if config.GOOGLE_API_KEY:
        genai.configure(api_key=config.GOOGLE_API_KEY)
        # Safety settings can be adjusted if needed, see Gemini docs
        # generation_config = {"temperature": 0.7} # Example config
        # safety_settings = [...]
        model = genai.GenerativeModel(
            'gemini-1.5-flash' # Or choose another suitable model like 'gemini-pro'
            # generation_config=generation_config,
            # safety_settings=safety_settings
        )
        logger.info(f"Google Generative AI configured with model: {model.model_name}")
    else:
        model = None
        logging.warning("GOOGLE_API_KEY not found in config. AI Analyzer will not function.")

except Exception as e:
    logger.error(f"Error configuring Google Generative AI: {e}", exc_info=True)
    model = None


# --- Analysis Function ---

def analyze_dns_batch(dns_query_list: list[dict]) -> list[dict] | None:
    """
    Analyzes a batch of DNS queries using the Gemini AI model.

    Args:
        dns_query_list: A list of dictionaries, each representing a processed
                        DNS query (from pihole_client.get_recent_queries).

    Returns:
        A list of dictionaries containing the analysis results for each
        unique domain, or None if analysis fails or the AI is not configured.
        Example item: {"domain": "example.com", "categories": ["Suspicious"], "reason": "Common ad tracker."}
    """
    if not model:
        logger.error("Gemini AI model is not configured. Cannot perform analysis.")
        return None

    if not dns_query_list:
        logger.info("No DNS queries provided for AI analysis.")
        return [] # Return empty list, not None

    # 1. Extract Unique Domains for Efficiency
    unique_domains = sorted(list(set(item['domain'] for item in dns_query_list if item.get('domain'))))
    if not unique_domains:
        logger.info("No valid domains found in the query list for AI analysis.")
        return []

    logger.info(f"Sending {len(unique_domains)} unique domains for AI analysis...")
    # Consider batching if len(unique_domains) is very large (e.g., > 500-1000) due to prompt size limits

    # 2. Construct the Prompt for Gemini
    #    This is crucial and may need tuning based on results.
    prompt = f"""
Analyze the following list of DNS domain names queried on a local network.
For each domain, determine if it falls into any of these categories:
- Malicious: Known malware, phishing, command & control (C&C), or other direct security threats.
- AdultContent: Pornography, explicit content unsuitable for minors.
- Gambling: Online betting, casinos, lottery sites.
- Dating: Online dating apps or services.
- Illegal: Sites promoting illegal activities (e.g., illegal streaming, illicit goods/services - use best judgment).
- Suspicious: Domains primarily used for aggressive advertising/tracking, potentially unwanted programs (PUPs), unusual TLDs often associated with spam/malware, or other activity that warrants caution but isn't overtly malicious.

Focus on the domain name itself and common knowledge about the services hosted there.

Provide the analysis STRICTLY in JSON format. The output should be a JSON list, where each element is an object containing:
- "domain": The domain name analyzed.
- "categories": A list of strings representing the categories matched (e.g., ["Malicious", "Gambling"]). If no categories match, provide an empty list [].
- "reason": A brief explanation for the categorization (e.g., "Known phishing domain pattern.", "Major online casino.", "Common advertising network.", "Benign service.").

Example JSON output format:
[
  {{ "domain": "google.com", "categories": [], "reason": "Benign search engine and services." }},
  {{ "domain": "badsite-example.xyz", "categories": ["Malicious"], "reason": "Matches patterns of known malicious domains on unusual TLD." }},
  {{ "domain": "trackingserv.net", "categories": ["Suspicious"], "reason": "Known advertising/tracking domain." }},
  {{ "domain": "casino-online.bet", "categories": ["Gambling"], "reason": "Likely online gambling site." }},
  {{ "domain": "adult-site.net", "categories": ["AdultContent"], "reason": "Domain name suggests adult content."}}
]

Analyze the following domains:
{json.dumps(unique_domains, indent=2)}

Return ONLY the JSON list, without any introductory text or explanation before or after the JSON structure.
"""
    # logging.debug(f"Prompt being sent to Gemini:\n{prompt}") # Uncomment to debug the exact prompt

    # 3. Call the Gemini API
    try:
        start_time = time.time()
        response = model.generate_content(prompt)
        end_time = time.time()
        logger.info(f"Gemini API call took {end_time - start_time:.2f} seconds.")

        # Log parts info if available (useful for debugging safety filters etc.)
        # if response.prompt_feedback:
        #     logging.debug(f"Gemini Prompt Feedback: {response.prompt_feedback}")
        # if response.candidates and response.candidates[0].finish_reason:
        #      logging.debug(f"Gemini Finish Reason: {response.candidates[0].finish_reason}")
        #      if response.candidates[0].finish_reason != 'STOP':
        #          logging.warning(f"Gemini generation finished unexpectedly: {response.candidates[0].finish_reason}")


        # 4. Parse the Response
        # Extract the text and try to parse it as JSON
        response_text = response.text.strip()
        # Sometimes the model might wrap the JSON in backticks (markdown code block)
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        # logging.debug(f"Raw response text from Gemini (cleaned):\n{response_text}") # Uncomment for debugging

        try:
            analysis_results = json.loads(response_text)
            # Basic validation: Is it a list? Do items look like dicts?
            if not isinstance(analysis_results, list):
                logger.error(f"AI analysis parsing error: Expected a JSON list, but got type {type(analysis_results)}. Response: {response_text[:500]}...") # Log truncated response
                return None
            # Further validation could check for 'domain', 'categories', 'reason' keys in list items

            logger.info(f"Successfully parsed AI analysis for {len(analysis_results)} domains.")
            return analysis_results

        except json.JSONDecodeError as json_err:
            logger.error(f"AI analysis parsing error: Failed to decode JSON. Error: {json_err}. Response: {response_text[:500]}...")
            return None
        except Exception as e:
             logger.error(f"An unexpected error occurred during AI response parsing: {e}", exc_info=True)
             return None


    except Exception as e:
        # Catch potential errors from the API call itself (e.g., connection, API key issues, content filtering)
        logger.error(f"An unexpected error occurred calling the Gemini API: {e}", exc_info=True)
        # Check if the exception has response details (specific to google.api_core.exceptions)
        # if hasattr(e, 'response') and e.response:
        #     logger.error(f"API Error Response: {e.response.text}")
        return None