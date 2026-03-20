import tldextract, Levenshtein, requests, socket, time, whois, csv
from datetime import datetime

def predict_url(url):
    reasons, risk_score = [], 0
    official_link = None
    passport = {
        "age": "Unknown", "registrar": "Private", "is_new": False, 
        "lat": 20.0, "lon": 0.0, "ssl": "Unknown", "server": "Unknown", 
        "redirects": 0, "hop_path": ""
    }
    
    if not url.startswith(('http://', 'https://')): url = 'https://' + url

    # LOCAL DB CHECK
    try:
        with open('data.csv', mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) == 2:
                    db_url = row[0].strip()
                    label = str(row[1]).strip()
                    if db_url == url or db_url == url.replace("https://", "http://"):
                        if label == '0':
                            return "✅ VERIFIED SAFE (DB)", 0, ["Found in internal safe database."], "Pre-verified official site.", passport, None
                        elif label == '1':
                            return "🚨 DANGEROUS THREAT (DB)", 99, ["Blacklisted in internal database!"], "Identified as a known phishing threat.", passport, None
    except Exception as e:
        pass 
        
    try:
        start_time = time.time()
        resp = requests.get(url, timeout=5, allow_redirects=True)
        load_speed = round((time.time() - start_time) * 1000)
        
        passport["server"] = resp.headers.get('Server', 'Hidden')
        passport["ssl"] = "Active (HTTPS)" if url.startswith('https') else "Insecure (HTTP)"
        
        # HOP TRACER
        passport["redirects"] = len(resp.history)
        if passport["redirects"] > 0:
            hops = [tldextract.extract(h.url).domain for h in resp.history] + [tldextract.extract(resp.url).domain]
            passport["hop_path"] = " ➔ ".join(hops)
            risk_score += (passport["redirects"] * 10)
            reasons.append(f"🔀 Redirects: URL hops {passport['redirects']} times before loading.")
            if passport["redirects"] >= 3:
                reasons.append("🚨 Evasion Tactic: Scammers use multiple redirects to bypass security!")

        # CONTENT SCANNER
        html_content = resp.text.lower()
        urgency_phrases = ['account suspended', 'verify identity', 'update kyc', 'limited time offer', 'claim your prize']
        found_phrases = [phrase for phrase in urgency_phrases if phrase in html_content]
        if found_phrases:
            risk_score += 40
            reasons.append(f"📄 Page Scan: Found malicious urgency phrases ➔ {', '.join(found_phrases)}")

        final_url = resp.url
        reasons.append(f"⚡ Speed: {load_speed}ms | Server: {passport['server']}")
    except Exception as e:
        final_url, risk_score = url, risk_score + 15
        reasons.append("⚠️ Connection: Server is unreachable or highly unstable.")

    ext = tldextract.extract(final_url)
    domain, reg_domain, suffix = ext.domain.lower(), ext.registered_domain.lower(), ext.suffix.lower()

    # WHOIS + Geo
    try:
        w = whois.whois(reg_domain)
        c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if c_date:
            age = (datetime.now() - c_date).days
            passport["age"] = f"{age} Days"
            passport["registrar"] = w.registrar or "Private"
            if age < 90: 
                passport["is_new"] = True
                risk_score += 40
    except: pass

    try:
        ip_addr = socket.gethostbyname(reg_domain)
        geo = requests.get(f"http://ip-api.com/json/{ip_addr}", timeout=2).json()
        passport["lat"], passport["lon"] = geo.get('lat', 20.0), geo.get('lon', 0.0)
    except: pass

    trusted = ['google.com', 'amazon.in', 'amazon.com', 'flipkart.com', 'paytm.com', 'meesho.com', 'ajio.com', 'nykaa.com']
    if reg_domain in trusted:
        return "✅ VERIFIED OFFICIAL", 0, ["Authenticated Brand Domain."], "This site is 100% official. Safe to use.", passport, None

    # BRAND SPOOFING
    brand_domains = {
        'google': 'https://www.google.com', 'amazon': 'https://www.amazon.in', 
        'flipkart': 'https://www.flipkart.com', 'paytm': 'https://paytm.com', 
        'meesho': 'https://www.meesho.com', 'ajio': 'https://www.ajio.com', 
        'nykaa': 'https://www.nykaa.com'
    }
    
    for b, official_url in brand_domains.items():
        if 0 < Levenshtein.distance(domain, b) <= 2:
            risk_score += 85
            reasons.append(f"🚨 Typosquatting: spelling mimics '{b}'.")
            official_link = official_url
        elif b in final_url and reg_domain not in trusted:
            risk_score += 70
            reasons.append(f"🚨 Brand Hijack: Unofficial use of '{b}' brand.")
            official_link = official_url

    phish_keywords = ['login', 'verify', 'secure', 'update', 'free', 'gift', 'win', 'offer', 'sale', 'reward']
    for word in phish_keywords:
        if word in final_url:
            risk_score += 20
            reasons.append(f"🚩 Keyword: Suspicious pattern '{word}' found.")

    if suffix in ['xyz', 'click', 'ml', 'ga', 'top', 'fake', 'cf', 'tk']:
        risk_score += 30
        reasons.append(f"⚠️ Extension: '.{suffix}' is high-risk.")

    risk_score = max(0, min(100, risk_score))
    if risk_score < 30: res, adv = "✅ POTENTIALLY SAFE", "Security clearance granted. Use with standard caution."
    elif risk_score < 75: res, adv = "⚠️ SUSPICIOUS LINK", "Warning! Multiple anomalies detected. Avoid payments."
    else: res, adv = "🚨 DANGEROUS THREAT", "CRITICAL! High phishing probability. Terminate session."
        
    return res, risk_score, reasons, adv, passport, official_link