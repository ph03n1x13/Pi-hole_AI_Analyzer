import ssl
import time
import config # Import configuration
import logging
import smtplib
from email.mime.text import MIMEText

# Setup basic logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_notification_email(subject: str, body_text: str) -> True | False:
    """
    Sends a notification email using SMTP settings from the config.

    Args:
        subject: The subject line of the email.
        body_text: The plain text content of the email body.

    Returns:
        True if the email was sent successfully, False otherwise.
    """
    # --- Retrieve and Validate Configuration ---
    smtp_server = config.SMTP_SERVER
    smtp_port = config.SMTP_PORT # Already converted to int in config.py
    sender_email = config.EMAIL_SENDER
    receiver_email = config.EMAIL_RECIPIENT
    password = config.SMTP_PASSWORD
    # Use config.SMTP_USERNAME if login username differs from sender email
    login_username = config.SMTP_USERNAME or sender_email # Default to sender if username not specified

    required_configs = {
        "SMTP Server": smtp_server,
        "SMTP Port": smtp_port,
        "Sender Email": sender_email,
        "Receiver Email": receiver_email,
        "Login Username": login_username, # Check the one we intend to use
        "SMTP Password": password,
    }

    missing_configs = [name for name, value in required_configs.items() if not value]
    if missing_configs:
        logger.error(f"Cannot send email. Missing required SMTP configurations: {', '.join(missing_configs)}")
        return False

    # Check if port conversion failed in config.py
    if not isinstance(smtp_port, int):
         logger.error(f"Cannot send email. Invalid SMTP_PORT configured: Must be an integer.")
         return False


    # --- Create the Email Message ---
    message = MIMEText(body_text, 'plain')
    message['Subject'] = subject
    message['From'] = sender_email
    message['To'] = receiver_email

    logger.info(f"Attempting to send email notification to {receiver_email} via {smtp_server}:{smtp_port}")

    # --- Connect and Send ---
    server = None # Initialize server to None
    try:
        # Create a secure SSL context
        context = ssl.create_default_context()

        # Decide connection method based on port (common practice)
        if smtp_port == 465:
            # Use SMTP_SSL for implicit SSL from the start
            logging.debug("Connecting using SMTP_SSL (Port 465)")
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, context=context, timeout=15)
            server.login(login_username, password) # Login might happen before or after connection for SSL
        else:
            # Assume STARTTLS for other ports (like 587)
            logging.debug(f"Connecting using SMTP and STARTTLS (Port {smtp_port})")
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
            server.ehlo() # Identify ourselves to the server
            server.starttls(context=context) # Secure the connection
            server.ehlo() # Re-identify ourselves over the secure connection
            server.login(login_username, password)

        # Send the email
        server.sendmail(sender_email, receiver_email, message.as_string())
        logger.info(f"Email notification sent successfully to {receiver_email}.")
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication Error: Failed to login to {smtp_server} with username {login_username}. Check username/password/app password. Error: {e}")
        return False
    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTP Connection Error: Failed to connect to {smtp_server}:{smtp_port}. Check server/port/firewall. Error: {e}")
        return False
    except smtplib.SMTPServerDisconnected:
        logger.error(f"SMTP Server Disconnected unexpectedly during operation with {smtp_server}.")
        return False
    except smtplib.SMTPException as e:
        # Catch other potential smtplib errors
        logger.error(f"SMTP Error occurred: {e}", exc_info=True)
        return False
    except TimeoutError:
         logger.error(f"Timeout occurred while trying to connect or communicate with {smtp_server}:{smtp_port}.")
         return False
    except ssl.SSLError as e:
         logger.error(f"SSL Error occurred, potentially during STARTTLS. Check port/server compatibility. Error: {e}")
         return False
    except OSError as e:
         # Catches potential network errors like "[Errno 111] Connection refused" or socket errors
         logger.error(f"Network or OS Error occurred connecting to {smtp_server}:{smtp_port}. Error: {e}")
         return False
    except Exception as e:
        logger.error(f"An unexpected error occurred sending email: {e}", exc_info=True)
        return False
    finally:
        # Ensure the connection is closed if it was established
        if server:
            try:
                server.quit()
                logging.debug("SMTP connection closed.")
            except Exception:
                 logging.warning("Error trying to quit SMTP server connection, might already be closed.", exc_info=False)