from flask import Flask, request, render_template, jsonify
import model  
import os
import time
import cv2
import numpy as np
import re

app = Flask(__name__)

# --- SCREENSHOT LOGIC ---
def take_live_screenshot(url):
    try:
        clean_url = url.replace("https://", "").replace("http://", "").split('/')[0]
        api_screenshot = f"https://s.wordpress.com/mshots/v1/http://{clean_url}?w=400&h=800"
        return api_screenshot
    except Exception as e:
        print(f"Screenshot Error: {e}")
        return "https://via.placeholder.com/400x800?text=Preview+Blocked+by+System"

# --- QR CODE EXTRACTOR (COMPUTER VISION) ---
def read_qr_from_image(image_file):
    try:
        file_bytes = np.frombuffer(image_file.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
        detector = cv2.QRCodeDetector()
        data, bbox, straight_qrcode = detector.detectAndDecode(img)
        if data: return data
        return None
    except Exception as e:
        return None

# --- TEXT ANALYZER (NLP & REGEX) ---
DANGER_WORDS = ['urgent', 'blocked', 'suspend', 'kyc', 'free', 'gift', 'click here', 'verify', 'update', 'account', 'password', 'prize', 'winner', 'claim', 'refund']

def analyze_sms_text(text):
    text_lower = text.lower()
    found_words = [word for word in DANGER_WORDS if word in text_lower]
    
    # Extract URL using Regex
    url_match = re.search(r'(https?://[^\s]+)|(www\.[^\s]+)', text)
    extracted_url = url_match.group(0) if url_match else None
    
    # Highlight danger words in HTML
    highlighted_text = text
    for word in found_words:
        pattern = re.compile(re.escape(word), re.IGNORECASE)
        highlighted_text = pattern.sub(f'<span style="color: #d93025; font-weight: 700; background: #fce8e6; padding: 2px 4px; border-radius: 3px; border: 1px solid #d93025;">{word}</span>', highlighted_text)

    return extracted_url, found_words, highlighted_text

# --- WEB UI ROUTE ---
@app.route('/', methods=['GET', 'POST'])
def home():
    result, risk, reasons, url, advice, official_link = "", 0, [], "", "", None
    qr_error = ""
    text_analysis = None
    passport = {
        "age": "Unknown", "registrar": "Private", "is_new": False, 
        "lat": 20.0, "lon": 0.0, "ssl": "Unknown", "server": "Unknown",
        "redirects": 0, "hop_path": ""       
    }
    screenshot_url = ""

    if request.method == 'POST':
        # Check which form was submitted
        url_input = request.form.get('url', '').strip()
        sms_input = request.form.get('sms_text', '').strip()
        
        # 1. Handle URL Input
        if url_input:
            url = url_input

        # 2. Handle SMS/Text Input
        elif sms_input:
            ext_url, found_words, highlighted_text = analyze_sms_text(sms_input)
            text_analysis = {"words": found_words, "html": highlighted_text}
            if ext_url:
                url = ext_url
                if not url.startswith('http'): url = 'https://' + url
            else:
                qr_error = "⚠️ No valid link found in the provided text. We only found text."

        # 3. Handle QR Code Input
        elif 'qr_file' in request.files:
            qr_file = request.files['qr_file']
            if qr_file.filename != '':
                extracted_data = read_qr_from_image(qr_file)
                if extracted_data and extracted_data.startswith(('http://', 'https://', 'www.')):
                    url = extracted_data
                else:
                    qr_error = "⚠️ Valid URL not found in the uploaded QR Code! Make sure it's a clear image."

        # Process the final URL if found
        if url:
            try:
                result, risk, reasons, advice, passport, official_link = model.predict_url(url)
                screenshot_url = take_live_screenshot(url)
            except Exception as e:
                print(f"Error during execution: {e}")
                result = "⚠️ SYSTEM ERROR"
                reasons = ["Internal engine failure. Please restart the terminal."]

    return render_template(
        'index.html', 
        result=result, risk=risk, reasons=reasons, 
        url=url, advice=advice, passport=passport, 
        screenshot_url=screenshot_url, official_link=official_link,
        qr_error=qr_error, text_analysis=text_analysis
    )

# ==========================================================
# 🔥 NEW: CHROME EXTENSION API GATEWAY
# ==========================================================
@app.route('/api/extension', methods=['GET'])
def extension_api():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    try:
        # Namma AI model-a background-la call pandrom
        result, risk, reasons, advice, passport, official_link = model.predict_url(url)
        return jsonify({
            "status": "success",
            "url": url,
            "result": result,
            "risk": risk,
            "reasons": reasons,
            "advice": advice,
            "official_link": official_link
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Browser Extension CORS block aagama irukka idhu theva
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

if __name__ == '__main__':
    print("🚀 CYBER SUITE & EXTENSION API RUNNING... Open http://127.0.0.1:5000")
    app.run(debug=True, port=5000)