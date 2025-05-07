# Hosted on https://faas-nyc1-2ef2e6cc.doserverless.co/api/v1/web/fn-8a419571-d5b5-47d2-852f-a153c3e81553/strongbox-mirror-one/pwned
# Responsible for keeping our HIBP API key on the server, rather than letting the app have it inside the bundle.
import os
import json
import base64
import requests
from urllib.parse import quote
from devicecheck import DeviceCheck

def verify_device_token(device_token: str, bundle_id: str, dev: bool) -> (bool, dict):
    """
    Verifies the device token using the 'devicecheck' package.
    """
    team_id = os.environ.get("APPLE_TEAM_ID")
    key_id = os.environ.get("APPLE_KEY_ID")
    private_key = os.environ.get("APPLE_PRIVATE_KEY")
    if private_key:
        private_key = private_key.replace("\\n", "\n")

    if not (team_id and key_id and private_key):
        return False, {"error": "Server configuration error: Missing Apple DeviceCheck credentials."}

    try:
        dc = DeviceCheck(
            key_id=key_id,
            team_id=team_id, 
            private_key="key.p8", 
            bundle_id=bundle_id, 
            dev_environment=dev
        )
        response = dc.validate_device_token(token=device_token)
        return True, response if response else {}
    except Exception as e:
        return False, {"error": "Device token validation failed", "details": str(e)}

def main(args: dict) -> dict:
    """
    DigitalOcean Functions entry point.
    """
    account = args.get("account")
    device_token = args.get("device_token")
    bundle_id = args.get("bundle_id")
    dev = args.get("dev")

    if args.get("http", {}).get("body"):
        try:
            decoded_str = base64.b64decode(args["http"]["body"]).decode("utf-8")
            data = json.loads(decoded_str)
            account = data.get("account", account)
            device_token = data.get("device_token", device_token)
            bundle_id = data.get("bundle_id", bundle_id)
            dev = data.get("dev", dev)
        except Exception as e:
            return {
                "body": json.dumps({"error": f"Error decoding request body: {str(e)}"}),
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"}
            }

    for param in ("account", "device_token", "bundle_id"):
        if not locals()[param]:
            return {
                "body": json.dumps({"error": f'Bad Request: Missing "{param}" parameter'}),
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"}
            }

    # Convert dev parameter to a boolean if it's provided as a string.
    if isinstance(dev, str):
        dev = dev.strip().lower() == "true"

    is_valid, validation_result = verify_device_token(device_token, bundle_id, dev)
    if not is_valid:
        return {
            "body": json.dumps({"error": "Device token validation failed", "details": validation_result}),
            "statusCode": 401,
            "headers": {"Content-Type": "application/json"}
        }

    hibp_api_key = os.environ.get("HIBP_API_KEY")
    if not hibp_api_key:
        return {
            "body": json.dumps({"error": "Server Error: Missing HIBP_API_KEY environment variable"}),
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"}
        }

    hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(account)}?truncateResponse=false"
    api_headers = {
        "hibp-api-key": hibp_api_key,
        "User-Agent": "DigitalOceanCloudFunction/1.0"
    }

    try:
        hibp_response = requests.get(hibp_url, headers=api_headers)
        try:
            response_body = hibp_response.json()
        except Exception:
            response_body = hibp_response.text

        return {
            "body": json.dumps(response_body),
            "statusCode": hibp_response.status_code,
            "headers": {"Content-Type": hibp_response.headers.get("Content-Type", "application/json")}
        }
    except Exception as e:
        return {
            "body": json.dumps({"error": "Internal Server Error", "details": str(e)}),
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"}
        }
