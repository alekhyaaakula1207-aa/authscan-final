import os
import re
import time
import warnings
warnings.filterwarnings("ignore")

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse

# Template folder works both locally and on Vercel
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, '..', 'templates')

app = Flask(__name__, template_folder=TEMPLATE_DIR)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
}

AUTH_CLASS_RE = re.compile(
    r"login|signin|sign.in|log.in|auth|account|credential|password|username|email.field",
    re.IGNORECASE,
)
AUTH_ID_RE = re.compile(
    r"login|signin|sign.in|log.in|auth|account|credential",
    re.IGNORECASE,
)
AUTH_ACTION_RE = re.compile(
    r"login|signin|sign.in|log.in|auth|session|token|account|password",
    re.IGNORECASE,
)


def fetch_html(url):
    try:
        session = requests.Session()
        session.headers.update(HEADERS)
        try:
            session.get(url, timeout=8, allow_redirects=True, verify=False)
        except Exception:
            pass
        response = session.get(url, timeout=10, allow_redirects=True, verify=False)
        response.raise_for_status()
        response.encoding = response.apparent_encoding or "utf-8"
        return response.text, None
    except requests.exceptions.Timeout:
        return None, "Request timed out. Site may be slow or blocking scrapers."
    except requests.exceptions.ConnectionError as e:
        return None, f"Cannot connect: {str(e)[:100]}"
    except requests.exceptions.HTTPError as e:
        return None, f"HTTP {e.response.status_code} — {e.response.reason}"
    except Exception as e:
        return None, str(e)[:200]


def score_element(el):
    score = 0
    classes = " ".join(el.get("class", []))
    el_id = el.get("id", "")
    action = el.get("action", "")
    if AUTH_CLASS_RE.search(classes): score += 6
    if AUTH_ID_RE.search(el_id):     score += 6
    if AUTH_ACTION_RE.search(action): score += 5
    inputs = el.find_all("input")
    has_pw   = any(i.get("type", "").lower() == "password" for i in inputs)
    has_text = any(
        i.get("type", "").lower() in ("text", "email", "") or not i.get("type")
        for i in inputs if i.get("type", "").lower() not in ("hidden", "submit", "button")
    )
    if has_pw:   score += 10
    if has_text: score += 3
    if el.find(["button", "input"], {"type": "submit"}): score += 2
    return score


def detect_fields(el):
    fields = []
    for inp in el.find_all("input"):
        t    = (inp.get("type") or "text").lower()
        meta = " ".join([
            inp.get("name", ""), inp.get("id", ""),
            inp.get("placeholder", ""), inp.get("autocomplete", "")
        ]).lower()
        if t == "password":
            fields.append("Password field")
        elif t == "email" or "email" in meta:
            fields.append("Email field")
        elif t == "text" and any(k in meta for k in ("user", "login", "name", "account", "phone")):
            fields.append("Username field")
        elif t == "checkbox" and any(k in meta for k in ("remember", "keep", "stay")):
            fields.append("Remember me")
        elif t in ("tel", "number") and any(k in meta for k in ("phone", "mobile", "otp", "code")):
            fields.append("Phone / OTP field")

    if el.find(["button", "input"], {"type": "submit"}):
        fields.append("Submit button")

    for a in el.find_all("a"):
        txt = (a.get_text() + a.get("href", "")).lower()
        if any(k in txt for k in ("forgot", "reset", "recover", "lost")):
            fields.append("Forgot password link")
            break

    for a in el.find_all("a"):
        txt = (a.get_text() + a.get("href", "")).lower()
        if any(k in txt for k in ("register", "sign up", "create account", "new account")):
            fields.append("Register / Sign-up link")
            break

    oauth_re = re.compile(r"google|github|facebook|twitter|apple|microsoft|sso|oauth|saml", re.I)
    for node in el.find_all(["a", "button", "div", "span"]):
        combined = " ".join(node.get("class", [])) + node.get_text() + node.get("href", "")
        if oauth_re.search(combined):
            fields.append("OAuth / Social login")
            break

    if el.find(class_=re.compile(r"captcha|recaptcha|hcaptcha|turnstile", re.I)):
        fields.append("CAPTCHA")

    if el.find(class_=re.compile(r"2fa|mfa|otp|two.?factor|authenticator", re.I)):
        fields.append("2FA / MFA")

    seen, out = set(), []
    for f in fields:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def determine_auth_type(fields):
    fs = set(fields)
    has_pw    = "Password field" in fs
    has_email = "Email field" in fs
    has_user  = "Username field" in fs
    has_oauth = "OAuth / Social login" in fs
    has_otp   = "Phone / OTP field" in fs
    if has_email and has_pw and has_oauth: return "Email + Password with Social Login"
    if has_user  and has_pw and has_oauth: return "Username + Password with Social Login"
    if has_email and has_pw:               return "Email + Password"
    if has_user  and has_pw:               return "Username + Password"
    if has_oauth and not has_pw:           return "OAuth / Social Login only"
    if has_otp:                            return "Phone / OTP Authentication"
    if has_pw:                             return "Password-based Authentication"
    return "Unknown / Non-standard"


def find_auth_component(html):
    soup = BeautifulSoup(html, "lxml")
    for tag in soup.find_all(["script", "style", "noscript", "svg", "iframe"]):
        tag.decompose()

    candidates = []

    for form in soup.find_all("form"):
        if form.find("input", {"type": "password"}):
            candidates.append((score_element(form) + 12, form, "form"))

    if not candidates:
        for pw in soup.find_all("input", {"type": "password"}):
            node = pw
            for _ in range(6):
                p = node.parent
                if not p or p.name in ("[document]", "body", "html"): break
                node = p
                if score_element(node) >= 5: break
            candidates.append((score_element(node) + 8, node, node.name))

    if not candidates:
        for tag in soup.find_all(["div", "section", "main", "article"]):
            s = score_element(tag)
            if s >= 8 and tag.find("input"):
                candidates.append((s, tag, tag.name))

    if not candidates:
        return {"found": False, "message": "No authentication component found."}

    candidates.sort(key=lambda x: x[0], reverse=True)
    _, best, tag_name = candidates[0]

    snippet = str(best)
    if len(snippet) > 10000:
        snippet = snippet[:10000] + "\n<!-- ... truncated ... -->"

    fields    = detect_fields(best)
    auth_type = determine_auth_type(fields)

    return {
        "found":         True,
        "html_snippet":  snippet,
        "fields":        fields,
        "auth_type":     auth_type,
        "container_tag": tag_name,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    body = request.get_json() or {}
    url  = body.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError
    except Exception:
        return jsonify({"error": "Invalid URL format"}), 400

    start = time.time()
    html, err = fetch_html(url)

    if err:
        return jsonify({"url": url, "found": False, "error": err, "elapsed": round(time.time() - start, 2)})

    result = find_auth_component(html)
    result["url"]          = url
    result["elapsed"]      = round(time.time() - start, 2)
    result["page_size_kb"] = round(len(html) / 1024, 1)
    return jsonify(result)


# ── Local development entry point ─────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 48)
    print("  AuthScan — Auth Component Detector")
    print("  Open: http://127.0.0.1:5000")
    print("=" * 48 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
