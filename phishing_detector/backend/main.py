from fastapi import FastAPI
import urllib.parse
import requests
import ipaddress
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import joblib
import pandas as pd
import os
import traceback

# Import TensorFlow for CNN
try:
    from tensorflow.keras.models import load_model
except ImportError:
    print("Warning: TensorFlow not installed. Load model will fail if CNN is required.")

app = FastAPI(title="Malicious URL Detector API")


app = FastAPI()


# Allow CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths to the saved models (in the same directory or upper directory)
SCALER_PATH = "scaler.pkl"
XGB_MODEL_PATH = "xgb_model.pkl"
CNN_MODEL_PATH = "cnn_model.h5"

scaler = None
xgb_model = None
cnn_model = None


@app.on_event("startup")
def load_ml_models():
    """Load the machine learning models into memory when the server starts."""
    global scaler, xgb_model, cnn_model
    try:
        if os.path.exists(SCALER_PATH):
            scaler = joblib.load(SCALER_PATH)
            print(f"Loaded scaler from {SCALER_PATH}")
        else:
            print(f"Warning: {SCALER_PATH} not found.")

        if os.path.exists(XGB_MODEL_PATH):
            xgb_model = joblib.load(XGB_MODEL_PATH)
            print(f"Loaded XGBoost model from {XGB_MODEL_PATH}")
        else:
            print(f"Warning: {XGB_MODEL_PATH} not found.")

        if os.path.exists(CNN_MODEL_PATH):
            cnn_model = load_model(CNN_MODEL_PATH)
            print(f"Loaded CNN model from {CNN_MODEL_PATH}")
        else:
            print(f"Warning: {CNN_MODEL_PATH} not found.")

    except Exception as e:
        print(f"Error loading models: {e}")


class URLRequest(BaseModel):
    url: str


def extract_features(url: str) -> np.ndarray:
    if not url.startswith('http'):
        url = 'https://' + url

    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    feats = []

    # 1-16: Basic Lexical metrics
    feats.append(len(url))  # url_len
    feats.append(url.count('@'))
    feats.append(url.count('?'))
    feats.append(url.count('-'))
    feats.append(url.count('='))
    feats.append(url.count('.'))
    feats.append(url.count('#'))
    feats.append(url.count('%'))
    feats.append(url.count('+'))
    feats.append(url.count('$'))
    feats.append(url.count('!'))
    feats.append(url.count('*'))
    feats.append(url.count(','))
    feats.append(url.count('//'))
    feats.append(sum(c.isdigit() for c in url))  # digits
    feats.append(sum(c.isalpha() for c in url))  # letters

    # 17-20: URL structural anomalies
    feats.append(1 if domain not in url else 0)  # abnormal_url
    feats.append(1 if parsed.scheme == 'https' else 0)  # https

    short_domains = ['bit.ly', 'goo.gl', 'shorte.st',
                     'tinyurl.com', 'is.gd', 'cli.gs', 'yfrog.com', 'ow.ly']
    feats.append(1 if any(s in domain for s in short_domains)
                 else 0)  # Shortining_Service

    try:
        ipaddress.ip_address(domain.split(':')[0])
        feats.append(1)  # having_ip_address
    except:
        feats.append(0)

    # 21-35: Web / Scraping features (Using fast approximations to prevent UI hanging)
    # Default to benign "live site" metrics just in case the site blocks our python script
    web_http_status = 200
    web_is_live = 1
    web_has_login = 0
    web_ssl_valid = 1 if url.startswith('https') else 0

    try:
        # Use a real browser user agent so YouTube/Cloudflare doesn't block us immediately
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36'}
        resp = requests.get(url, headers=headers, timeout=3, verify=False)
        web_http_status = resp.status_code
        if 'login' in resp.text.lower() or 'password' in resp.text.lower() or 'sign in' in resp.text.lower():
            web_has_login = 1
    except:
        pass

    feats.extend([
        web_http_status,    # web_http_status
        web_is_live,        # web_is_live
        0,                  # web_ext_ratio (mock)
        1,                  # web_unique_domains (mock safe)
        1,                  # web_favicon (mock safe)
        1,                  # web_csp (mock safe)
        1,                  # web_xframe (mock safe)
        1,                  # web_hsts (mock safe)
        1,                  # web_xcontent (mock safe)
        100,                # web_security_score (mock safe)
        1,                  # web_forms_count (mock)
        0,                  # web_password_fields (mock)
        0,                  # web_hidden_inputs (mock)
        web_has_login,      # web_has_login
        web_ssl_valid       # web_ssl_valid
    ])

    # 36-59: Phishing heuristic analysis
    url_lower = url.lower()
    urgency_words = ['urgent', 'verify', 'update',
                     'suspend', 'restricted', 'alert']
    # phish_urgency_words
    feats.append(sum(1 for w in urgency_words if w in url_lower))

    sec_words = ['secure', 'auth', 'login', 'account', 'banking', 'signin']
    # phish_security_words
    feats.append(sum(1 for w in sec_words if w in url_lower))

    feats.append(1 if 'brand' in url_lower else 0)  # phish_brand_mentions
    feats.append(0)  # phish_brand_hijack
    # phish_multiple_subdomains
    feats.append(1 if domain.count('.') > 2 else 0)
    feats.append(1 if len(path) > 30 else 0)  # phish_long_path
    feats.append(1 if url.count('&') > 3 else 0)  # phish_many_params

    susp_tlds = ['.xyz', '.top', '.win', '.bid',
                 '.stream', '.gq', '.tk', '.ml', '.cf']
    feats.append(1 if any(domain.endswith(t)
                 for t in susp_tlds) else 0)  # phish_suspicious_tld

    feats.append(0)  # phish_adv_exact_brand_match
    feats.append(0)  # phish_adv_brand_in_subdomain
    feats.append(0)  # phish_adv_brand_in_path
    feats.append(domain.count('-'))  # phish_adv_hyphen_count
    feats.append(sum(c.isdigit() for c in domain))  # phish_adv_number_count
    feats.append(1 if any(domain.endswith(t)
                 for t in susp_tlds) else 0)  # phish_adv_suspicious_tld
    feats.append(1 if len(domain) > 30 else 0)  # phish_adv_long_domain
    # phish_adv_many_subdomains
    feats.append(1 if domain.count('.') > 3 else 0)
    feats.append(path.count('%'))  # phish_adv_encoded_chars
    feats.append(1 if any(w in path for w in sec_words)
                 else 0)  # phish_adv_path_keywords
    feats.append(1 if url.count('//') > 1 else 0)  # phish_adv_has_redirect
    feats.append(1 if url.count('&') > 4 else 0)  # phish_adv_many_params

    feats.append(1 if 'hack' in path else 0)  # path_has_hacked_terms
    susp_ext = ['.exe', '.zip', '.rar', '.js', '.vbs', '.scr', '.bin']
    feats.append(1 if any(path.endswith(ext)
                 for ext in susp_ext) else 0)  # suspicious_extension
    feats.append(path.count('_'))  # path_underscore_count
    feats.append(1 if domain.endswith('.gov')
                 or domain.endswith('.edu') else 0)  # is_gov_edu

    # Ensure shape is exactly (1, 59)
    return np.array([feats], dtype=float)


@app.post("/predict")
def predict_url(request: URLRequest):
    global scaler, xgb_model, cnn_model

    # If the user hasn't copied the actual model files into the backend folder yet,
    # we return a simulated prediction so the frontend UI can still be tested and demonstrated.
    if scaler is None or xgb_model is None or cnn_model is None:
        import random
        # Simulate some realistic-looking probabilities
        xgb_prob = random.uniform(0.01, 0.99)
        cnn_prob = random.uniform(0.01, 0.99)
        ens_prob = (xgb_prob + cnn_prob) / 2
        ens_pred = 1 if ens_prob > 0.5 else 0

        return {
            "url": request.url,
            "prediction": "Malicious" if ens_pred == 1 else "Legitimate",
            "ensemble_probability": float(ens_prob),
            "xgb_probability": float(xgb_prob),
            "cnn_probability": float(cnn_prob),
            "note": "MODELS NOT FOUND. This is a simulated response for UI testing."
        }

    try:
        # 1. Extract exactly 59 features from the URL
        features = extract_features(request.url)

        if features.shape[1] != 59:
            raise ValueError(f"Expected 59 features, got {features.shape[1]}")

        # 2. Scale features
        scaled_features = scaler.transform(features)

        # 3. XGBoost Prediction
        xgb_probs = xgb_model.predict_proba(scaled_features)[:, 1]

        # 4. CNN Prediction
        cnn_input = scaled_features.reshape(
            scaled_features.shape[0], scaled_features.shape[1], 1)
        cnn_probs = cnn_model.predict(cnn_input).flatten()

        # 5. Ensemble Average
        ensemble_probs = (xgb_probs + cnn_probs) / 2
        ensemble_preds = (ensemble_probs > 0.5).astype(int)

        is_malicious = int(ensemble_preds[0]) == 1

        return {
            "url": request.url,
            "prediction": "Malicious" if is_malicious else "Legitimate",
            "ensemble_probability": float(ensemble_probs[0]),
            "xgb_probability": float(xgb_probs[0]),
            "cnn_probability": float(cnn_probs[0]),
        }

    except Exception as e:
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
