from flask import Flask, request, jsonify
import joblib
import numpy as np
import re
import tldextract
from urllib.parse import urlparse

app = Flask(__name__)

# Load the trained model and scaler
model = joblib.load("../model/phishing_model.pkl")
scaler = joblib.load("../model/scaler.pkl")

def extract_features(url):
    parsed_url = urlparse(url)
    domain_info = tldextract.extract(url)

    length_url = len(url)
    length_hostname = len(parsed_url.netloc)
    ip = 0
    nb_dots = url.count('.')
    nb_hyphens = url.count('-')
    nb_at = url.count('@')
    nb_qm = url.count('?')
    nb_and = url.count('&')
    nb_or = url.count('|')
    nb_eq = url.count('=')
    nb_underscore = url.count('_')
    nb_tilde = url.count('~')
    nb_percent = url.count('%')
    nb_slash = url.count('/')
    nb_star = url.count('*')
    nb_colon = url.count(':')
    nb_comma = url.count(',')
    nb_semicolumn = url.count(';')
    nb_dollar = url.count('$')
    nb_space = url.count(' ')
    nb_www = url.count('www')
    nb_com = url.count('.com')
    nb_dslash = url.count('//')


    http_in_path = 1 if "http" in parsed_url.path else 0
    https_token = 1 if "https" in url else 0
    ratio_digits_url = sum(c.isdigit() for c in url) / len(url)
    ratio_digits_host = sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc)
    punycode = 1 if "xn--" in url else 0
    port = parsed_url.port if parsed_url.port else 0
    tld_in_path = 1 if domain_info.suffix in parsed_url.path else 0
    tld_in_subdomain = 1 if domain_info.suffix in domain_info.subdomain else 0
    abnormal_subdomain = 1 if parsed_url.netloc.count('.') > 3 else 0
    nb_subdomains = parsed_url.netloc.count('.')

    prefix_suffix = 1 if '-' in parsed_url.netloc else 0
    random_domain = 0
    shortening_service = 1 if any(short in url for short in ["bit.ly", "goo.gl", "tinyurl"]) else 0
    path_extension = 1 if parsed_url.path.endswith(('.php', '.html', '.asp')) else 0
    nb_redirection = url.count('//') - 1
    nb_external_redirection = 0


    length_words_raw = len(re.findall(r'\w+', url))
    char_repeat = max([url.count(char) for char in set(url)]) if url else 0
    shortest_words_raw = min([len(word) for word in url.split("/")]) if url else 0
    shortest_word_host = min([len(word) for word in parsed_url.netloc.split(".")]) if parsed_url.netloc else 0
    shortest_word_path = min([len(word) for word in parsed_url.path.split("/")]) if parsed_url.path else 0
    longest_words_raw = max([len(word) for word in url.split("/")]) if url else 0
    longest_word_host = max([len(word) for word in parsed_url.netloc.split(".")]) if parsed_url.netloc else 0
    longest_word_path = max([len(word) for word in parsed_url.path.split("/")]) if parsed_url.path else 0
    avg_words_raw = length_words_raw / max(url.count('/'), 1)
    avg_word_host = len(parsed_url.netloc) / max(parsed_url.netloc.count('.'), 1)
    avg_word_path = len(parsed_url.path) / max(parsed_url.path.count('/'), 1)


    phish_hints = url.lower().count("secure") + url.lower().count("account")
    domain_in_brand = 0
    brand_in_subdomain = 0
    brand_in_path = 0
    suspecious_tld = 1 if domain_info.suffix in ["tk", "ml", "cf", "ga", "gq"] else 0
    statistical_report = 0
    nb_hyperlinks = 5
    ratio_intHyperlinks = 0.7
    ratio_extHyperlinks = 0.3
    ratio_nullHyperlinks = 0.1
    nb_extCSS = 1
    ratio_intRedirection = 0.5
    ratio_extRedirection = 0.5
    ratio_intErrors = 0.2
    ratio_extErrors = 0.3
    login_form = 1
    external_favicon = 0
    links_in_tags = 5
    submit_email = 0
    ratio_intMedia = 0.6
    ratio_extMedia = 0.4
    sfh = 0
    iframe = 0
    popup_window = 1
    safe_anchor = 1
    onmouseover = 0
    right_clic = 0
    empty_title = 0
    domain_in_title = 0
    domain_with_copyright = 1
    whois_registered_domain = 0
    domain_registration_length = 50
    domain_age = 2000
    web_traffic = 50000
    dns_record = 1
    google_index = 1
    page_rank = 3

    feature_vector = np.array([
        length_url, length_hostname, ip, nb_dots, nb_hyphens, nb_at, nb_qm, nb_and, nb_or,
        nb_eq, nb_underscore, nb_tilde, nb_percent, nb_slash, nb_star, nb_colon, nb_comma,
        nb_semicolumn, nb_dollar, nb_space, nb_www, nb_com, nb_dslash, http_in_path,
        https_token, ratio_digits_url, ratio_digits_host, punycode, port, tld_in_path,
        tld_in_subdomain, abnormal_subdomain, nb_subdomains, prefix_suffix, random_domain,
        shortening_service, path_extension, nb_redirection, nb_external_redirection,
        length_words_raw, char_repeat, shortest_words_raw, shortest_word_host, shortest_word_path,
        longest_words_raw, longest_word_host, longest_word_path, avg_words_raw, avg_word_host, avg_word_path,
        phish_hints, domain_in_brand, brand_in_subdomain, brand_in_path, suspecious_tld,
        statistical_report, nb_hyperlinks, ratio_intHyperlinks, ratio_extHyperlinks, ratio_nullHyperlinks,
        nb_extCSS, ratio_intRedirection, ratio_extRedirection, ratio_intErrors, ratio_extErrors, login_form,
        external_favicon, links_in_tags, submit_email, ratio_intMedia, ratio_extMedia, sfh, iframe, popup_window,
        safe_anchor, onmouseover, right_clic, empty_title, domain_in_title, domain_with_copyright,
        whois_registered_domain, domain_registration_length, domain_age, web_traffic, dns_record, google_index, page_rank
    ]).reshape(1, -1)

    return feature_vector

@app.route("/")
def home():
    return "Phishing Detection API is running!"

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json  
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is required"}), 400

        features = extract_features(url)
        features_scaled = scaler.transform(features)
        prediction = model.predict(features_scaled)
        
        result = "Legitimate" if prediction[0] == 1 else "Phishing"
        
        return jsonify({"url": url, "prediction": result})

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
