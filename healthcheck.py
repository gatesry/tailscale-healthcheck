import os
import requests
from datetime import datetime, timedelta
from flask import Flask, jsonify, redirect
import pytz
import logging  # Add logging for debugging
from threading import Timer  # For token renewal
from urllib3.exceptions import ProtocolError  # Add import for better error handling
from http.client import RemoteDisconnected  # Add import for better error handling
import fnmatch  # Add for wildcard pattern matching
from dateutil import parser  # Add this import

def get_log_level_from_env(default=logging.INFO):
    """Return a logging level from LOG_LEVEL env var, defaulting to INFO.

    Accepts standard level names like DEBUG, INFO, WARNING, ERROR, CRITICAL.
    Falls back to the provided default if the value is missing or invalid.
    """
    level_name = os.getenv("LOG_LEVEL", "INFO")
    return getattr(logging, str(level_name).upper(), default)

# Configure logging with safe default (INFO) and env override
logging.basicConfig(level=get_log_level_from_env())

app = Flask(__name__)
app.url_map.strict_slashes = False  # Allow trailing slashes to be ignored

# Load configuration from environment variables
TAILNET_DOMAIN = os.getenv("TAILNET_DOMAIN", "example.com")  # Default to "example.com"
TAILSCALE_API_URL = f"https://api.tailscale.com/api/v2/tailnet/{TAILNET_DOMAIN}/devices"
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "your-default-token")
ONLINE_THRESHOLD_MINUTES = int(os.getenv("ONLINE_THRESHOLD_MINUTES", 5))  # Default to 5 minutes
KEY_THRESHOLD_MINUTES = int(os.getenv("KEY_THRESHOLD_MINUTES", 1440))  # Default to 1440 minutes
GLOBAL_HEALTHY_THRESHOLD = int(os.getenv("GLOBAL_HEALTHY_THRESHOLD", 100))
GLOBAL_ONLINE_HEALTHY_THRESHOLD = int(os.getenv("GLOBAL_ONLINE_HEALTHY_THRESHOLD", 100))
GLOBAL_KEY_HEALTHY_THRESHOLD = int(os.getenv("GLOBAL_KEY_HEALTHY_THRESHOLD", 100))
GLOBAL_UPDATE_HEALTHY_THRESHOLD = int(os.getenv("GLOBAL_UPDATE_HEALTHY_THRESHOLD", 100))
UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH = os.getenv("UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH", "NO").upper() == "YES"
DISPLAY_SETTINGS_IN_OUTPUT = os.getenv("DISPLAY_SETTINGS_IN_OUTPUT", "NO").upper() == "YES"

PORT = int(os.getenv("PORT", 5000))  # Default to port 5000
TIMEZONE = os.getenv("TIMEZONE", "UTC")  # Default to UTC

# Filter configurations
INCLUDE_OS = os.getenv("INCLUDE_OS", "").strip()
EXCLUDE_OS = os.getenv("EXCLUDE_OS", "").strip()
INCLUDE_IDENTIFIER = os.getenv("INCLUDE_IDENTIFIER", "").strip()
EXCLUDE_IDENTIFIER = os.getenv("EXCLUDE_IDENTIFIER", "").strip()
INCLUDE_TAGS = os.getenv("INCLUDE_TAGS", "").strip()
EXCLUDE_TAGS = os.getenv("EXCLUDE_TAGS", "").strip()
INCLUDE_IDENTIFIER_UPDATE_HEALTHY = os.getenv("INCLUDE_IDENTIFIER_UPDATE_HEALTHY", "").strip()
EXCLUDE_IDENTIFIER_UPDATE_HEALTHY = os.getenv("EXCLUDE_IDENTIFIER_UPDATE_HEALTHY", "").strip()
INCLUDE_TAG_UPDATE_HEALTHY = os.getenv("INCLUDE_TAG_UPDATE_HEALTHY", "").strip()
EXCLUDE_TAG_UPDATE_HEALTHY = os.getenv("EXCLUDE_TAG_UPDATE_HEALTHY", "").strip()

# Load OAuth configuration from environment variables
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")

# Global variable to store the OAuth access token and timer
ACCESS_TOKEN = None
TOKEN_RENEWAL_TIMER = None

# Global variable to track if it's the initial token fetch
IS_INITIAL_FETCH = True

def fetch_oauth_token():
    """
    Fetches a new OAuth access token using the client ID and client secret.
    """
    global ACCESS_TOKEN, TOKEN_RENEWAL_TIMER, IS_INITIAL_FETCH
    try:
        response = requests.post(
            "https://api.tailscale.com/api/v2/oauth/token",
            data={
                "client_id": OAUTH_CLIENT_ID,
                "client_secret": OAUTH_CLIENT_SECRET
            }
        )
        response.raise_for_status()
        token_data = response.json()
        ACCESS_TOKEN = token_data["access_token"]
        logging.info("Successfully fetched OAuth access token.")

        # Cancel any existing timer before scheduling a new one
        if TOKEN_RENEWAL_TIMER:
            TOKEN_RENEWAL_TIMER.cancel()

        # Schedule the next token renewal after 50 minutes
        TOKEN_RENEWAL_TIMER = Timer(50 * 60, fetch_oauth_token)
        TOKEN_RENEWAL_TIMER.start()

        # Log the token renewal time only if it's not the initial fetch
        if not IS_INITIAL_FETCH:
            try:
                tz = pytz.timezone(TIMEZONE)
                renewal_time = datetime.now(tz).isoformat()
                logging.info(f"OAuth access token renewed at {renewal_time} ({TIMEZONE}).")
            except pytz.UnknownTimeZoneError:
                logging.error(f"Unknown timezone: {TIMEZONE}. Logging renewal time in UTC.")
                logging.info(f"OAuth access token renewed at {datetime.utcnow().isoformat()} UTC.")
        else:
            IS_INITIAL_FETCH = False  # Mark the initial fetch as complete
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error during token fetch: {http_err}")
        if response.status_code == 401:
            logging.error("Unauthorized error (401). Retrying token fetch...")
            ACCESS_TOKEN = None
        else:
            logging.error(f"Unexpected HTTP error: {response.status_code}")
    except Exception as e:
        logging.error(f"Failed to fetch OAuth access token: {e}")
        ACCESS_TOKEN = None

def initialize_oauth():
    """
    Initializes OAuth token fetching if OAuth is configured.
    This function should only be called once during the master process initialization.
    """
    if OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET:
        logging.info("OAuth configuration detected. Fetching initial access token...")
        fetch_oauth_token()

# Only initialize OAuth in the Gunicorn master process
if os.getenv("GUNICORN_MASTER_PROCESS", "false").lower() == "true":
    initialize_oauth()

# Log the configured timezone
logging.debug(f"Configured TIMEZONE: {TIMEZONE}")

def make_authenticated_request(url, headers):
    """
    Makes an authenticated request to the given URL and handles 401 errors by refreshing the token.
    """
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 401:
            logging.error("Unauthorized error (401). Attempting to refresh OAuth token...")
            fetch_oauth_token()  # Immediately refresh the token
            if ACCESS_TOKEN:  # Retry the request with the new token
                headers["Authorization"] = f"Bearer {ACCESS_TOKEN}"
                response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response
    except (RemoteDisconnected, ProtocolError) as e:
        logging.error(f"Connection error during authenticated request: {e}. Retrying...")
        return make_authenticated_request(url, headers)  # Retry the request
    except Exception as e:
        logging.error(f"Error during authenticated request: {e}")
        raise

def should_include_device(device):
    """
    Check if a device should be included based on filter settings
    """
    # Get device identifiers
    identifiers = [
        device["hostname"].lower(),
        device["id"].lower(),
        device["name"].lower(),
        device["name"].split('.')[0].lower()  # machineName
    ]
    
    # Get device tags without 'tag:' prefix
    device_tags = [tag.replace('tag:', '') for tag in device.get("tags", [])]

    # Tag filtering - check if any device tag matches any pattern
    if INCLUDE_TAGS and INCLUDE_TAGS.strip() != "":
        tag_patterns = [p.strip() for p in INCLUDE_TAGS.split(",") if p.strip()]
        if tag_patterns:
            # Device must have at least one tag that matches any pattern
            if not any(any(fnmatch.fnmatch(tag, pattern) for pattern in tag_patterns) for tag in device_tags):
                return False
    elif EXCLUDE_TAGS and EXCLUDE_TAGS.strip() != "":
        tag_patterns = [p.strip() for p in EXCLUDE_TAGS.split(",") if p.strip()]
        if tag_patterns:
            # Device must not have any tag that matches any pattern
            if any(any(fnmatch.fnmatch(tag, pattern) for pattern in tag_patterns) for tag in device_tags):
                return False

    # OS filtering
    if INCLUDE_OS and INCLUDE_OS.strip() != "":
        os_patterns = [p.strip() for p in INCLUDE_OS.split(",") if p.strip()]
        if not os_patterns:  # Skip if no valid patterns after cleaning
            return True
        if not any(fnmatch.fnmatch(device["os"], pattern) for pattern in os_patterns):
            return False
    elif EXCLUDE_OS and EXCLUDE_OS.strip() != "":
        os_patterns = [p.strip() for p in EXCLUDE_OS.split(",") if p.strip()]
        if not os_patterns:  # Skip if no valid patterns after cleaning
            return True
        if any(fnmatch.fnmatch(device["os"], pattern) for pattern in os_patterns):
            return False

    # Identifier filtering
    if INCLUDE_IDENTIFIER and INCLUDE_IDENTIFIER.strip() != "":
        identifier_patterns = [p.strip().lower() for p in INCLUDE_IDENTIFIER.split(",") if p.strip()]
        if not identifier_patterns:  # Skip if no valid patterns after cleaning
            return True
        if not any(any(fnmatch.fnmatch(identifier, pattern) for pattern in identifier_patterns) for identifier in identifiers):
            return False
    elif EXCLUDE_IDENTIFIER and EXCLUDE_IDENTIFIER.strip() != "":
        identifier_patterns = [p.strip().lower() for p in EXCLUDE_IDENTIFIER.split(",") if p.strip()]
        if not identifier_patterns:  # Skip if no valid patterns after cleaning
            return True
        if any(any(fnmatch.fnmatch(identifier, pattern) for pattern in identifier_patterns) for identifier in identifiers):
            return False

    return True

def should_force_update_healthy(device):
    """
    Check if a device should have forced update_healthy status based on identifier and tag filters
    """
    identifiers = [
        device["hostname"].lower(),
        device["id"].lower(),
        device["name"].lower(),
        device["name"].split('.')[0].lower()  # machineName
    ]
    
    device_tags = [tag.replace('tag:', '').lower() for tag in device.get("tags", [])]
    
    # Check EXCLUDE_TAG_UPDATE_HEALTHY
    if EXCLUDE_TAG_UPDATE_HEALTHY:
        tag_patterns = [p.strip().lower() for p in EXCLUDE_TAG_UPDATE_HEALTHY.split(",") if p.strip()]
        if tag_patterns and any(any(fnmatch.fnmatch(tag, pattern) for pattern in tag_patterns) for tag in device_tags):
            return True
            
    # Check INCLUDE_TAG_UPDATE_HEALTHY
    if INCLUDE_TAG_UPDATE_HEALTHY:
        tag_patterns = [p.strip().lower() for p in INCLUDE_TAG_UPDATE_HEALTHY.split(",") if p.strip()]
        if tag_patterns:
            return not any(any(fnmatch.fnmatch(tag, pattern) for pattern in tag_patterns) for tag in device_tags)
    
    # Check EXCLUDE_IDENTIFIER_UPDATE_HEALTHY
    if EXCLUDE_IDENTIFIER_UPDATE_HEALTHY:
        patterns = [p.strip().lower() for p in EXCLUDE_IDENTIFIER_UPDATE_HEALTHY.split(",") if p.strip()]
        if patterns and any(any(fnmatch.fnmatch(identifier, pattern) for pattern in patterns) for identifier in identifiers):
            return True
            
    # Check INCLUDE_IDENTIFIER_UPDATE_HEALTHY
    if INCLUDE_IDENTIFIER_UPDATE_HEALTHY:
        patterns = [p.strip().lower() for p in INCLUDE_IDENTIFIER_UPDATE_HEALTHY.split(",") if p.strip()]
        if patterns:
            return not any(any(fnmatch.fnmatch(identifier, pattern) for pattern in patterns) for identifier in identifiers)
            
    return False

def remove_tag_prefix(tags):
    if not tags:
        return []
    return [tag.replace('tag:', '') for tag in tags]

@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Determine the authorization method
        if OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET and ACCESS_TOKEN:
            auth_header = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
        else:
            auth_header = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        # Fetch data from Tailscale API using the helper function
        response = make_authenticated_request(TAILSCALE_API_URL, auth_header)
        devices = response.json().get("devices", [])

        # Get the timezone object
        try:
            tz = pytz.timezone(TIMEZONE)
        except pytz.UnknownTimeZoneError:
            logging.error(f"Unknown timezone: {TIMEZONE}")
            return jsonify({"error": f"Unknown timezone: {TIMEZONE}"}), 400

        # Calculate the threshold time (now - ONLINE_THRESHOLD_MINUTES) in the specified timezone
        threshold_time = datetime.now(tz) - timedelta(minutes=ONLINE_THRESHOLD_MINUTES)
        logging.debug(f"Threshold time: {threshold_time.isoformat()}")

        # Check health status for each device
        health_status = []
        counter_healthy_true = 0
        counter_healthy_false = 0
        counter_healthy_online_true = 0
        counter_healthy_online_false = 0
        counter_key_healthy_true = 0
        counter_key_healthy_false = 0
        counter_update_healthy_true = 0
        counter_update_healthy_false = 0

        for device in devices:
            # Apply filters
            if not should_include_device(device):
                continue

            last_seen = parser.isoparse(device["lastSeen"]).replace(tzinfo=pytz.UTC)
            last_seen_local = last_seen.astimezone(tz)
            expires = None
            key_healthy = True if device.get("keyExpiryDisabled", False) else True
            key_days_to_expire = None
            if not device.get("keyExpiryDisabled", False) and device.get("expires"):
                expires = parser.isoparse(device["expires"]).replace(tzinfo=pytz.UTC)
                expires = expires.astimezone(tz)
                time_until_expiry = expires - datetime.now(tz)
                key_healthy = time_until_expiry.total_seconds() / 60 > KEY_THRESHOLD_MINUTES
                key_days_to_expire = time_until_expiry.days

            online_is_healthy = last_seen_local >= threshold_time
            update_is_healthy = should_force_update_healthy(device) or not device.get("updateAvailable", False)
            key_healthy = True if device.get("keyExpiryDisabled", False) else key_healthy
            is_healthy = online_is_healthy and key_healthy
            if UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH:
                is_healthy = is_healthy and update_is_healthy

            # Update counters
            if is_healthy:
                counter_healthy_true += 1
            else:
                counter_healthy_false += 1

            if online_is_healthy:
                counter_healthy_online_true += 1
            else:
                counter_healthy_online_false += 1

            if key_healthy:
                counter_key_healthy_true += 1
            else:
                counter_key_healthy_false += 1

            # Update update healthy counters
            if not device.get("updateAvailable", False):
                counter_update_healthy_true += 1
            else:
                counter_update_healthy_false += 1

            machine_name = device["name"].split('.')[0]
            health_info = {
                "id": device["id"],
                "device": device["name"],
                "machineName": machine_name,
                "hostname": device["hostname"],
                "os": device["os"],
                "clientVersion": device.get("clientVersion", ""),
                "updateAvailable": device.get("updateAvailable", False),
                "update_healthy": should_force_update_healthy(device) or not device.get("updateAvailable", False),
                "lastSeen": last_seen_local.isoformat(),
                "online_healthy": online_is_healthy,
                "keyExpiryDisabled": device.get("keyExpiryDisabled", False),
                "key_healthy": key_healthy,
                "key_days_to_expire": key_days_to_expire,
                "healthy": is_healthy,
                "tags": remove_tag_prefix(device.get("tags", []))
            }
            
            if not device.get("keyExpiryDisabled", False):
                health_info["keyExpiryTimestamp"] = expires.isoformat() if expires else None
            
            health_status.append(health_info)

        # Add counters and global health metrics to response
        settings = {
            "TAILNET_DOMAIN": TAILNET_DOMAIN,
            "OAUTH_CLIENT_ID": OAUTH_CLIENT_ID if OAUTH_CLIENT_ID else "not configured",
            "OAUTH_CLIENT_SECRET": "********" if OAUTH_CLIENT_SECRET else "not configured",
            "AUTH_TOKEN": "********" if AUTH_TOKEN and AUTH_TOKEN != "your-default-token" else "not configured",
            "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
            "ONLINE_THRESHOLD_MINUTES": ONLINE_THRESHOLD_MINUTES,
            "KEY_THRESHOLD_MINUTES": KEY_THRESHOLD_MINUTES,
            "GLOBAL_HEALTHY_THRESHOLD": GLOBAL_HEALTHY_THRESHOLD,
            "GLOBAL_ONLINE_HEALTHY_THRESHOLD": GLOBAL_ONLINE_HEALTHY_THRESHOLD,
            "GLOBAL_KEY_HEALTHY_THRESHOLD": GLOBAL_KEY_HEALTHY_THRESHOLD,
            "GLOBAL_UPDATE_HEALTHY_THRESHOLD": GLOBAL_UPDATE_HEALTHY_THRESHOLD,
            "UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH": UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH,
            "DISPLAY_SETTINGS_IN_OUTPUT": DISPLAY_SETTINGS_IN_OUTPUT,
            "TIMEZONE": TIMEZONE,
            "INCLUDE_OS": INCLUDE_OS if INCLUDE_OS else "",
            "EXCLUDE_OS": EXCLUDE_OS if EXCLUDE_OS else "",
            "INCLUDE_IDENTIFIER": INCLUDE_IDENTIFIER if INCLUDE_IDENTIFIER else "",
            "EXCLUDE_IDENTIFIER": EXCLUDE_IDENTIFIER if EXCLUDE_IDENTIFIER else "",
            "INCLUDE_TAGS": INCLUDE_TAGS if INCLUDE_TAGS else "",
            "EXCLUDE_TAGS": EXCLUDE_TAGS if EXCLUDE_TAGS else "",
            "INCLUDE_IDENTIFIER_UPDATE_HEALTHY": INCLUDE_IDENTIFIER_UPDATE_HEALTHY if INCLUDE_IDENTIFIER_UPDATE_HEALTHY else "",
            "EXCLUDE_IDENTIFIER_UPDATE_HEALTHY": EXCLUDE_IDENTIFIER_UPDATE_HEALTHY if EXCLUDE_IDENTIFIER_UPDATE_HEALTHY else "",
            "INCLUDE_TAG_UPDATE_HEALTHY": INCLUDE_TAG_UPDATE_HEALTHY if INCLUDE_TAG_UPDATE_HEALTHY else "",
            "EXCLUDE_TAG_UPDATE_HEALTHY": EXCLUDE_TAG_UPDATE_HEALTHY if EXCLUDE_TAG_UPDATE_HEALTHY else ""
        }

        response = {
            "devices": health_status,
            "metrics": {
                "counter_healthy_true": counter_healthy_true,
                "counter_healthy_false": counter_healthy_false,
                "counter_healthy_online_true": counter_healthy_online_true,
                "counter_healthy_online_false": counter_healthy_online_false,
                "counter_key_healthy_true": counter_key_healthy_true,
                "counter_key_healthy_false": counter_key_healthy_false,
                "counter_update_healthy_true": counter_update_healthy_true,
                "counter_update_healthy_false": counter_update_healthy_false,
                "global_healthy": counter_healthy_false <= GLOBAL_HEALTHY_THRESHOLD,
                "global_key_healthy": counter_key_healthy_false <= GLOBAL_KEY_HEALTHY_THRESHOLD,
                "global_online_healthy": counter_healthy_online_false <= GLOBAL_ONLINE_HEALTHY_THRESHOLD,
                "global_update_healthy": counter_update_healthy_false <= GLOBAL_UPDATE_HEALTHY_THRESHOLD
            }
        }
        
        if DISPLAY_SETTINGS_IN_OUTPUT:
            response["settings"] = settings

        return jsonify(response)

    except Exception as e:
        logging.error(f"Error in health_check: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health/', methods=['GET'])
def health_check_redirect():
    # Redirect to /health without trailing slash
    return redirect('/health', code=301)

@app.route('/health/<identifier>', methods=['GET'])
def health_check_by_identifier(identifier):
    try:
        # Determine the authorization method
        if OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET and ACCESS_TOKEN:
            auth_header = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
        else:
            auth_header = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        # Fetch data from Tailscale API using the helper function
        response = make_authenticated_request(TAILSCALE_API_URL, auth_header)
        devices = response.json().get("devices", [])

        # Get the timezone object
        try:
            tz = pytz.timezone(TIMEZONE)
        except pytz.UnknownTimeZoneError:
            logging.error(f"Unknown timezone: {TIMEZONE}")
            return jsonify({"error": f"Unknown timezone: {TIMEZONE}"}), 400

        # Calculate the threshold time (now - ONLINE_THRESHOLD_MINUTES) in the specified timezone
        threshold_time = datetime.now(tz) - timedelta(minutes=ONLINE_THRESHOLD_MINUTES)
        logging.debug(f"Threshold time: {threshold_time.isoformat()}")

        # Convert identifier to lowercase for case-insensitive comparison
        identifier_lower = identifier.lower()

        # Initialize counters
        counter_healthy_true = 0
        counter_healthy_false = 0
        counter_healthy_online_true = 0
        counter_healthy_online_false = 0
        counter_key_healthy_true = 0
        counter_key_healthy_false = 0
        counter_update_healthy_true = 0
        counter_update_healthy_false = 0

        # Find the device with the matching hostname, ID, name, or machineName
        for device in devices:
            machine_name = device["name"].split('.')[0]  # Extract machine name before the first dot
            if (
                device["hostname"].lower() == identifier_lower
                or device["id"].lower() == identifier_lower
                or device["name"].lower() == identifier_lower
                or machine_name.lower() == identifier_lower
            ):
                last_seen = parser.isoparse(device["lastSeen"]).replace(tzinfo=pytz.UTC)
                last_seen_local = last_seen.astimezone(tz)  # Convert lastSeen to the specified timezone
                expires = None
                key_healthy = True if device.get("keyExpiryDisabled", False) else True
                key_days_to_expire = None
                if not device.get("keyExpiryDisabled", False) and device.get("expires"):
                    expires = parser.isoparse(device["expires"]).replace(tzinfo=pytz.UTC)
                    expires = expires.astimezone(tz)
                    time_until_expiry = expires - datetime.now(tz)
                    key_healthy = time_until_expiry.total_seconds() / 60 > KEY_THRESHOLD_MINUTES
                    key_days_to_expire = time_until_expiry.days

                logging.debug(f"Device {device['name']} last seen (local): {last_seen_local.isoformat()}")
                online_is_healthy = last_seen_local >= threshold_time
                update_is_healthy = should_force_update_healthy(device) or not device.get("updateAvailable", False)
                key_healthy = True if device.get("keyExpiryDisabled", False) else key_healthy
                is_healthy = online_is_healthy and key_healthy
                if UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH:
                    is_healthy = is_healthy and update_is_healthy

                # Count only this specific device
                counter_healthy_true = 1 if is_healthy else 0
                counter_healthy_false = 0 if is_healthy else 1
                counter_healthy_online_true = 1 if online_is_healthy else 0
                counter_healthy_online_false = 0 if online_is_healthy else 1
                counter_key_healthy_true = 1 if key_healthy else 0
                counter_key_healthy_false = 0 if key_healthy else 1

                # Update update healthy counters
                if not device.get("updateAvailable", False):
                    counter_update_healthy_true += 1
                else:
                    counter_update_healthy_false += 1

                health_info = {
                    "id": device["id"],
                    "device": device["name"],
                    "machineName": machine_name,
                    "hostname": device["hostname"],
                    "os": device["os"],
                    "clientVersion": device.get("clientVersion", ""),
                    "updateAvailable": device.get("updateAvailable", False),
                    "update_healthy": should_force_update_healthy(device) or not device.get("updateAvailable", False),
                    "lastSeen": last_seen_local.isoformat(),  # Include timezone offset in ISO format
                    "online_healthy": online_is_healthy,
                    "keyExpiryDisabled": device.get("keyExpiryDisabled", False),
                    "key_healthy": key_healthy,
                    "key_days_to_expire": key_days_to_expire,
                    "healthy": online_is_healthy and key_healthy,
                    "tags": remove_tag_prefix(device.get("tags", []))
                }
                
                if not device.get("keyExpiryDisabled", False):
                    health_info["keyExpiryTimestamp"] = expires.isoformat() if expires else None
                
                settings = {
                    "TAILNET_DOMAIN": TAILNET_DOMAIN,
                    "OAUTH_CLIENT_ID": OAUTH_CLIENT_ID if OAUTH_CLIENT_ID else "not configured",
                    "OAUTH_CLIENT_SECRET": "********" if OAUTH_CLIENT_SECRET else "not configured",
                    "AUTH_TOKEN": "********" if AUTH_TOKEN and AUTH_TOKEN != "your-default-token" else "not configured",
                    "ONLINE_THRESHOLD_MINUTES": ONLINE_THRESHOLD_MINUTES,
                    "KEY_THRESHOLD_MINUTES": KEY_THRESHOLD_MINUTES,
                    "GLOBAL_HEALTHY_THRESHOLD": GLOBAL_HEALTHY_THRESHOLD,
                    "GLOBAL_ONLINE_HEALTHY_THRESHOLD": GLOBAL_ONLINE_HEALTHY_THRESHOLD,
                    "GLOBAL_KEY_HEALTHY_THRESHOLD": GLOBAL_KEY_HEALTHY_THRESHOLD,
                    "GLOBAL_UPDATE_HEALTHY_THRESHOLD": GLOBAL_UPDATE_HEALTHY_THRESHOLD,
                    "UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH": UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH,
                    "DISPLAY_SETTINGS_IN_OUTPUT": DISPLAY_SETTINGS_IN_OUTPUT,
                    "TIMEZONE": TIMEZONE,
                    "INCLUDE_OS": INCLUDE_OS if INCLUDE_OS else "",
                    "EXCLUDE_OS": EXCLUDE_OS if EXCLUDE_OS else "",
                    "INCLUDE_IDENTIFIER": INCLUDE_IDENTIFIER if INCLUDE_IDENTIFIER else "",
                    "EXCLUDE_IDENTIFIER": EXCLUDE_IDENTIFIER if EXCLUDE_IDENTIFIER else "",
                    "INCLUDE_TAGS": INCLUDE_TAGS if INCLUDE_TAGS else "",
                    "EXCLUDE_TAGS": EXCLUDE_TAGS if EXCLUDE_TAGS else "",
                    "INCLUDE_IDENTIFIER_UPDATE_HEALTHY": INCLUDE_IDENTIFIER_UPDATE_HEALTHY if INCLUDE_IDENTIFIER_UPDATE_HEALTHY else "",
                    "EXCLUDE_IDENTIFIER_UPDATE_HEALTHY": EXCLUDE_IDENTIFIER_UPDATE_HEALTHY if EXCLUDE_IDENTIFIER_UPDATE_HEALTHY else "",
                    "INCLUDE_TAG_UPDATE_HEALTHY": INCLUDE_TAG_UPDATE_HEALTHY if INCLUDE_TAG_UPDATE_HEALTHY else "",
                    "EXCLUDE_TAG_UPDATE_HEALTHY": EXCLUDE_TAG_UPDATE_HEALTHY if EXCLUDE_TAG_UPDATE_HEALTHY else ""
                }

                response = {
                    "device": health_info,
                    "metrics": {
                        "counter_healthy_true": counter_healthy_true,
                        "counter_healthy_false": counter_healthy_false,
                        "counter_healthy_online_true": counter_healthy_online_true,
                        "counter_healthy_online_false": counter_healthy_online_false,
                        "counter_key_healthy_true": counter_key_healthy_true,
                        "counter_key_healthy_false": counter_key_healthy_false,
                        "counter_update_healthy_true": counter_update_healthy_true,
                        "counter_update_healthy_false": counter_update_healthy_false,
                        "global_healthy": counter_healthy_false <= GLOBAL_HEALTHY_THRESHOLD,
                        "global_key_healthy": counter_key_healthy_false <= GLOBAL_KEY_HEALTHY_THRESHOLD,
                        "global_online_healthy": counter_healthy_online_false <= GLOBAL_ONLINE_HEALTHY_THRESHOLD,
                        "global_update_healthy": counter_update_healthy_false <= GLOBAL_UPDATE_HEALTHY_THRESHOLD
                    }
                }
                
                if DISPLAY_SETTINGS_IN_OUTPUT:
                    response["settings"] = settings
                
                return jsonify(response)

        # If no matching hostname, ID, name, or machineName is found
        return jsonify({"error": "Device not found"}), 404

    except Exception as e:
        logging.error(f"Error in health_check_by_identifier: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health/unhealthy', methods=['GET'])
def health_check_unhealthy():
    try:
        # Determine the authorization method
        if OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET and ACCESS_TOKEN:
            auth_header = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
        else:
            auth_header = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        # Fetch data from Tailscale API using the helper function
        response = make_authenticated_request(TAILSCALE_API_URL, auth_header)
        devices = response.json().get("devices", [])

        # Get the timezone object
        try:
            tz = pytz.timezone(TIMEZONE)
        except pytz.UnknownTimeZoneError:
            logging.error(f"Unknown timezone: {TIMEZONE}")
            return jsonify({"error": f"Unknown timezone: {TIMEZONE}"}), 400

        # Calculate the threshold time (now - ONLINE_THRESHOLD_MINUTES) in the specified timezone
        threshold_time = datetime.now(tz) - timedelta(minutes=ONLINE_THRESHOLD_MINUTES)
        logging.debug(f"Threshold time: {threshold_time.isoformat()}")

        # Initialize counters
        counter_healthy_true = 0
        counter_healthy_false = 0
        counter_healthy_online_true = 0
        counter_healthy_online_false = 0
        counter_key_healthy_true = 0
        counter_key_healthy_false = 0
        counter_update_healthy_true = 0
        counter_update_healthy_false = 0

        # Check health status for each device and filter unhealthy devices
        unhealthy_devices = []
        for device in devices:
            last_seen = parser.isoparse(device["lastSeen"]).replace(tzinfo=pytz.UTC)
            last_seen_local = last_seen.astimezone(tz)  # Convert lastSeen to the specified timezone
            expires = None
            key_healthy = True if device.get("keyExpiryDisabled", False) else True
            key_days_to_expire = None
            if not device.get("keyExpiryDisabled", False) and device.get("expires"):
                expires = parser.isoparse(device["expires"]).replace(tzinfo=pytz.UTC)
                expires = expires.astimezone(tz)
                time_until_expiry = expires - datetime.now(tz)
                key_healthy = time_until_expiry.total_seconds() / 60 > KEY_THRESHOLD_MINUTES
                key_days_to_expire = time_until_expiry.days

            logging.debug(f"Device {device['name']} last seen (local): {last_seen_local.isoformat()}")
            online_is_healthy = last_seen_local >= threshold_time
            update_is_healthy = should_force_update_healthy(device) or not device.get("updateAvailable", False)
            key_healthy = True if device.get("keyExpiryDisabled", False) else key_healthy
            is_healthy = online_is_healthy and key_healthy
            if UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH:
                is_healthy = is_healthy and update_is_healthy

            if not is_healthy:
                # Count only unhealthy devices that will be output
                counter_healthy_false += 1
                if not online_is_healthy:
                    counter_healthy_online_false += 1
                else:
                    counter_healthy_online_true += 1
                if not key_healthy:
                    counter_key_healthy_false += 1
                else:
                    counter_key_healthy_true += 1

                # Update update healthy counters
                if not device.get("updateAvailable", False):
                    counter_update_healthy_true += 1
                else:
                    counter_update_healthy_false += 1

                machine_name = device["name"].split('.')[0]  # Extract machine name before the first dot
                health_info = {
                    "id": device["id"],
                    "device": device["name"],
                    "machineName": machine_name,
                    "hostname": device["hostname"],
                    "os": device["os"],
                    "clientVersion": device.get("clientVersion", ""),
                    "updateAvailable": device.get("updateAvailable", False),
                    "update_healthy": should_force_update_healthy(device) or not device.get("updateAvailable", False),
                    "lastSeen": last_seen_local.isoformat(),  # Include timezone offset in ISO format
                    "online_healthy": online_is_healthy,
                    "keyExpiryDisabled": device.get("keyExpiryDisabled", False),
                    "key_healthy": key_healthy,
                    "key_days_to_expire": key_days_to_expire,
                    "healthy": online_is_healthy and key_healthy,
                    "tags": remove_tag_prefix(device.get("tags", []))
                }
                
                if not device.get("keyExpiryDisabled", False):
                    health_info["keyExpiryTimestamp"] = expires.isoformat() if expires else None
                
                unhealthy_devices.append(health_info)

        settings = {
            "TAILNET_DOMAIN": TAILNET_DOMAIN,
            "OAUTH_CLIENT_ID": OAUTH_CLIENT_ID if OAUTH_CLIENT_ID else "not configured",
            "OAUTH_CLIENT_SECRET": "********" if OAUTH_CLIENT_SECRET else "not configured",
            "AUTH_TOKEN": "********" if AUTH_TOKEN and AUTH_TOKEN != "your-default-token" else "not configured",
            "ONLINE_THRESHOLD_MINUTES": ONLINE_THRESHOLD_MINUTES,
            "KEY_THRESHOLD_MINUTES": KEY_THRESHOLD_MINUTES,
            "GLOBAL_HEALTHY_THRESHOLD": GLOBAL_HEALTHY_THRESHOLD,
            "GLOBAL_ONLINE_HEALTHY_THRESHOLD": GLOBAL_ONLINE_HEALTHY_THRESHOLD,
            "GLOBAL_KEY_HEALTHY_THRESHOLD": GLOBAL_KEY_HEALTHY_THRESHOLD,
            "GLOBAL_UPDATE_HEALTHY_THRESHOLD": GLOBAL_UPDATE_HEALTHY_THRESHOLD,
            "UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH": UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH,
            "DISPLAY_SETTINGS_IN_OUTPUT": DISPLAY_SETTINGS_IN_OUTPUT,
            "TIMEZONE": TIMEZONE,
            "INCLUDE_OS": INCLUDE_OS if INCLUDE_OS else "",
            "EXCLUDE_OS": EXCLUDE_OS if EXCLUDE_OS else "",
            "INCLUDE_IDENTIFIER": INCLUDE_IDENTIFIER if INCLUDE_IDENTIFIER else "",
            "EXCLUDE_IDENTIFIER": EXCLUDE_IDENTIFIER if EXCLUDE_IDENTIFIER else "",
            "INCLUDE_TAGS": INCLUDE_TAGS if INCLUDE_TAGS else "",
            "EXCLUDE_TAGS": EXCLUDE_TAGS if EXCLUDE_TAGS else "",
            "INCLUDE_IDENTIFIER_UPDATE_HEALTHY": INCLUDE_IDENTIFIER_UPDATE_HEALTHY if INCLUDE_IDENTIFIER_UPDATE_HEALTHY else "",
            "EXCLUDE_IDENTIFIER_UPDATE_HEALTHY": EXCLUDE_IDENTIFIER_UPDATE_HEALTHY if EXCLUDE_IDENTIFIER_UPDATE_HEALTHY else "",
            "INCLUDE_TAG_UPDATE_HEALTHY": INCLUDE_TAG_UPDATE_HEALTHY if INCLUDE_TAG_UPDATE_HEALTHY else "",
            "EXCLUDE_TAG_UPDATE_HEALTHY": EXCLUDE_TAG_UPDATE_HEALTHY if EXCLUDE_TAG_UPDATE_HEALTHY else ""
        }

        response = {
            "devices": unhealthy_devices,
            "metrics": {
                "counter_healthy_true": counter_healthy_true,
                "counter_healthy_false": counter_healthy_false,
                "counter_healthy_online_true": counter_healthy_online_true,
                "counter_healthy_online_false": counter_healthy_online_false,
                "counter_key_healthy_true": counter_key_healthy_true,
                "counter_key_healthy_false": counter_key_healthy_false,
                "counter_update_healthy_true": counter_update_healthy_true,
                "counter_update_healthy_false": counter_update_healthy_false,
                "global_key_healthy": counter_key_healthy_false <= GLOBAL_KEY_HEALTHY_THRESHOLD,
                "global_online_healthy": counter_healthy_online_false <= GLOBAL_ONLINE_HEALTHY_THRESHOLD,
                "global_healthy": counter_healthy_false <= GLOBAL_HEALTHY_THRESHOLD,
                "global_update_healthy": counter_update_healthy_false <= GLOBAL_UPDATE_HEALTHY_THRESHOLD
            }
        }
        
        if DISPLAY_SETTINGS_IN_OUTPUT:
            response["settings"] = settings

        return jsonify(response)

    except Exception as e:
        logging.error(f"Error in health_check_unhealthy: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health/healthy', methods=['GET'])
def health_check_healthy():
    try:
        # Determine the authorization method
        if OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET and ACCESS_TOKEN:
            auth_header = {"Authorization": f"Bearer {ACCESS_TOKEN}"}
        else:
            auth_header = {"Authorization": f"Bearer {AUTH_TOKEN}"}

        # Fetch data from Tailscale API using the helper function
        response = make_authenticated_request(TAILSCALE_API_URL, auth_header)
        devices = response.json().get("devices", [])

        # Get the timezone object
        try:
            tz = pytz.timezone(TIMEZONE)
        except pytz.UnknownTimeZoneError:
            logging.error(f"Unknown timezone: {TIMEZONE}")
            return jsonify({"error": f"Unknown timezone: {TIMEZONE}"}), 400

        # Calculate the threshold time (now - ONLINE_THRESHOLD_MINUTES) in the specified timezone
        threshold_time = datetime.now(tz) - timedelta(minutes=ONLINE_THRESHOLD_MINUTES)
        logging.debug(f"Threshold time: {threshold_time.isoformat()}")

        # Initialize counters
        counter_healthy_true = 0
        counter_healthy_false = 0
        counter_healthy_online_true = 0
        counter_healthy_online_false = 0
        counter_key_healthy_true = 0
        counter_key_healthy_false = 0
        counter_update_healthy_true = 0
        counter_update_healthy_false = 0

        # Check health status for each device and filter healthy devices
        healthy_devices = []
        for device in devices:
            last_seen = parser.isoparse(device["lastSeen"]).replace(tzinfo=pytz.UTC)
            last_seen_local = last_seen.astimezone(tz)  # Convert lastSeen to the specified timezone
            expires = None
            key_healthy = True if device.get("keyExpiryDisabled", False) else True
            key_days_to_expire = None
            if not device.get("keyExpiryDisabled", False) and device.get("expires"):
                expires = parser.isoparse(device["expires"]).replace(tzinfo=pytz.UTC)
                expires = expires.astimezone(tz)
                time_until_expiry = expires - datetime.now(tz)
                key_healthy = time_until_expiry.total_seconds() / 60 > KEY_THRESHOLD_MINUTES
                key_days_to_expire = time_until_expiry.days

            logging.debug(f"Device {device['name']} last seen (local): {last_seen_local.isoformat()}")
            online_is_healthy = last_seen_local >= threshold_time
            update_is_healthy = should_force_update_healthy(device) or not device.get("updateAvailable", False)
            key_healthy = True if device.get("keyExpiryDisabled", False) else key_healthy
            is_healthy = online_is_healthy and key_healthy
            if UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH:
                is_healthy = is_healthy and update_is_healthy

            if is_healthy:
                # Count only healthy devices that will be output
                counter_healthy_true += 1
                counter_healthy_online_true += 1
                counter_key_healthy_true += 1

                # Update update healthy counters
                if not device.get("updateAvailable", False):
                    counter_update_healthy_true += 1
                else:
                    counter_update_healthy_false += 1

                machine_name = device["name"].split('.')[0]  # Extract machine name before the first dot
                health_info = {
                    "id": device["id"],
                    "device": device["name"],
                    "machineName": machine_name,
                    "hostname": device["hostname"],
                    "os": device["os"],
                    "clientVersion": device.get("clientVersion", ""),
                    "updateAvailable": device.get("updateAvailable", False),
                    "update_healthy": should_force_update_healthy(device) or not device.get("updateAvailable", False),
                    "lastSeen": last_seen_local.isoformat(),  # Include timezone offset in ISO format
                    "online_healthy": online_is_healthy,
                    "keyExpiryDisabled": device.get("keyExpiryDisabled", False),
                    "key_healthy": key_healthy,
                    "key_days_to_expire": key_days_to_expire,
                    "healthy": online_is_healthy and key_healthy,
                    "tags": remove_tag_prefix(device.get("tags", []))
                }
                
                if not device.get("keyExpiryDisabled", False):
                    health_info["keyExpiryTimestamp"] = expires.isoformat() if expires else None
                
                healthy_devices.append(health_info)

        settings = {
            "TAILNET_DOMAIN": TAILNET_DOMAIN,
            "OAUTH_CLIENT_ID": OAUTH_CLIENT_ID if OAUTH_CLIENT_ID else "not configured",
            "OAUTH_CLIENT_SECRET": "********" if OAUTH_CLIENT_SECRET else "not configured",
            "AUTH_TOKEN": "********" if AUTH_TOKEN and AUTH_TOKEN != "your-default-token" else "not configured",
            "ONLINE_THRESHOLD_MINUTES": ONLINE_THRESHOLD_MINUTES,
            "KEY_THRESHOLD_MINUTES": KEY_THRESHOLD_MINUTES,
            "GLOBAL_HEALTHY_THRESHOLD": GLOBAL_HEALTHY_THRESHOLD,
            "GLOBAL_ONLINE_HEALTHY_THRESHOLD": GLOBAL_ONLINE_HEALTHY_THRESHOLD,
            "GLOBAL_KEY_HEALTHY_THRESHOLD": GLOBAL_KEY_HEALTHY_THRESHOLD,
            "GLOBAL_UPDATE_HEALTHY_THRESHOLD": GLOBAL_UPDATE_HEALTHY_THRESHOLD,
            "UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH": UPDATE_HEALTHY_IS_INCLUDED_IN_HEALTH,
            "DISPLAY_SETTINGS_IN_OUTPUT": DISPLAY_SETTINGS_IN_OUTPUT,
            "TIMEZONE": TIMEZONE,
            "INCLUDE_OS": INCLUDE_OS if INCLUDE_OS else "",
            "EXCLUDE_OS": EXCLUDE_OS if EXCLUDE_OS else "",
            "INCLUDE_IDENTIFIER": INCLUDE_IDENTIFIER if INCLUDE_IDENTIFIER else "",
            "EXCLUDE_IDENTIFIER": EXCLUDE_IDENTIFIER if EXCLUDE_IDENTIFIER else "",
            "INCLUDE_TAGS": INCLUDE_TAGS if INCLUDE_TAGS else "",
            "EXCLUDE_TAGS": EXCLUDE_TAGS if EXCLUDE_TAGS else "",
            "INCLUDE_IDENTIFIER_UPDATE_HEALTHY": INCLUDE_IDENTIFIER_UPDATE_HEALTHY if INCLUDE_IDENTIFIER_UPDATE_HEALTHY else "",
            "EXCLUDE_IDENTIFIER_UPDATE_HEALTHY": EXCLUDE_IDENTIFIER_UPDATE_HEALTHY if EXCLUDE_IDENTIFIER_UPDATE_HEALTHY else "",
            "INCLUDE_TAG_UPDATE_HEALTHY": INCLUDE_TAG_UPDATE_HEALTHY if INCLUDE_TAG_UPDATE_HEALTHY else "",
            "EXCLUDE_TAG_UPDATE_HEALTHY": EXCLUDE_TAG_UPDATE_HEALTHY if EXCLUDE_TAG_UPDATE_HEALTHY else ""
        }

        response = {
            "devices": healthy_devices,
            "metrics": {
                "counter_healthy_true": counter_healthy_true,
                "counter_healthy_false": counter_healthy_false,
                "counter_healthy_online_true": counter_healthy_online_true,
                "counter_healthy_online_false": counter_healthy_online_false,
                "counter_key_healthy_true": counter_key_healthy_true,
                "counter_key_healthy_false": counter_key_healthy_false,
                "counter_update_healthy_true": counter_update_healthy_true,
                "counter_update_healthy_false": counter_update_healthy_false,
                "global_key_healthy": counter_key_healthy_false <= GLOBAL_KEY_HEALTHY_THRESHOLD,
                "global_online_healthy": counter_healthy_online_false <= GLOBAL_ONLINE_HEALTHY_THRESHOLD,
                "global_healthy": counter_healthy_false <= GLOBAL_HEALTHY_THRESHOLD,
                "global_update_healthy": counter_update_healthy_false <= GLOBAL_UPDATE_HEALTHY_THRESHOLD
            }
        }
        
        if DISPLAY_SETTINGS_IN_OUTPUT:
            response["settings"] = settings

        return jsonify(response)

    except Exception as e:
        logging.error(f"Error in health_check_healthy: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
