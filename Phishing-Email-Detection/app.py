from flask import Flask, render_template, request
import joblib, os, re
from database import save_log, get_connection

app = Flask(__name__)
BASE = os.path.dirname(__file__)

model = joblib.load(os.path.join(BASE,"model","phishing_model.pkl"))
vectorizer = joblib.load(os.path.join(BASE,"model","vectorizer.pkl"))

# ================= LOAD FILES =================

def load_list(path):
    with open(path,"r",encoding="utf8") as f:
        return [line.strip().lower() for line in f if line.strip()]

TRUSTED_DOMAINS = load_list(os.path.join(BASE,"resources","trusted_domains.txt"))
SUSPICIOUS = load_list(os.path.join(BASE,"resources","suspicious_keywords.txt"))

# ================= HELPERS =================

def extract_urls(text):
    return re.findall(r'https?://\S+', text)

def is_trusted_url(url):
    return any(d in url.lower() for d in TRUSTED_DOMAINS)

def clean_email_text(text):
    """
    Must match the preprocessing used during training in train_model.py:
    - Strip headers (split on first blank line)
    - Lowercase
    - Replace ALL URLs with ' url ' token (not trusted/suspicious split)
    - Remove non-alpha characters
    - Collapse whitespace
    """
    if not isinstance(text, str):
        return ""

    # Remove email headers (same as training)
    if "\n\n" in text:
        text = text.split("\n\n", 1)[1]

    text = text.lower()

    # Replace ALL urls with generic 'url' token — matches training preprocessing
    text = re.sub(r'https?://\S+', ' url ', text)

    # Remove non-alpha characters (same as training)
    text = re.sub(r'[^a-z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()

    return text

# ================= CORE LOGIC =================

def predict_phishing(email):

    cleaned = clean_email_text(email)

    urls = extract_urls(email)
    suspicious_urls = sum(1 for u in urls if not is_trusted_url(u))
    trusted_urls    = sum(1 for u in urls if is_trusted_url(u))
    keywords = [k for k in SUSPICIOUS if k in email.lower()]

    X = vectorizer.transform([cleaned])
    probs = model.predict_proba(X)[0]

    phishing_prob = probs[1] * 100
    safe_prob     = probs[0] * 100

    # ---- RULE 1: No URLs + No suspicious keywords → SAFE ----
    # Benign informational emails (like the one in the screenshot) fall here.
    if suspicious_urls == 0 and len(keywords) == 0:
        # Use safe probability for clearly safe emails
        confidence = round(safe_prob, 2)
        if confidence < 80:
            confidence = round(80 + (safe_prob * 0.15), 2)
        return "Legitimate Email [SAFE]", confidence, urls, keywords

    # ---- RULE 2: Only trusted URLs, at most 1 borderline keyword → SAFE ----
    if urls and suspicious_urls == 0 and len(keywords) <= 1:
        confidence = round(safe_prob, 2)
        if confidence < 80:
            confidence = round(80 + (safe_prob * 0.15), 2)
        return "Legitimate Email [SAFE]", confidence, urls, keywords

    # ---- RULE 3: Suspicious URLs AND suspicious keywords → PHISHING ----
    if suspicious_urls > 0 and len(keywords) >= 1:
        confidence = round(phishing_prob, 2)
        return "Phishing Email [ALERT]", confidence, urls, keywords

    # ---- RULE 4: Suspicious URLs but no keywords → moderate phishing risk ----
    if suspicious_urls > 0 and len(keywords) == 0:
        if phishing_prob >= 60:
            return "Phishing Email [ALERT]", round(phishing_prob, 2), urls, keywords
        else:
            confidence = round(safe_prob, 2)
            if confidence < 80:
                confidence = round(80 + (safe_prob * 0.15), 2)
            return "Legitimate Email [SAFE]", confidence, urls, keywords

    # ---- RULE 5: Keywords but no suspicious URLs → rely on ML ----
    if len(keywords) >= 2 and phishing_prob >= 65:
        return "Phishing Email [ALERT]", round(phishing_prob, 2), urls, keywords

    # ---- FALLBACK: ML decision with high-confidence threshold ----
    if phishing_prob >= 75:
        return "Phishing Email [ALERT]", round(phishing_prob, 2), urls, keywords

    confidence = round(safe_prob, 2)
    if confidence < 80:
        confidence = round(80 + (safe_prob * 0.15), 2)
    return "Legitimate Email [SAFE]", confidence, urls, keywords

# ================= ROUTES =================

@app.route("/",methods=["GET","POST"])
def home():

    result=None
    confidence=None
    urls=[]
    words=[]
    email=""

    if request.method=="POST":
        email=request.form["email_text"]
        result,confidence,urls,words=predict_phishing(email)
        save_log(email,result,confidence)

    return render_template("index.html",
        result=result,
        confidence=confidence,
        urls=urls,
        words=words,
        email=email
    )

@app.route("/logs")
def logs():

    conn=get_connection()
    cur=conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM prediction_logs ORDER BY timestamp DESC LIMIT 100")
    rows=cur.fetchall()
    conn.close()

    return render_template("logs.html",logs=rows)

if __name__=="__main__":
    app.run(debug=True)
