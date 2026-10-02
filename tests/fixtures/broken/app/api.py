import os
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
# Открытый CORS для любого сайта + куки.
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",
}


@app.after_request
def add_cors_headers(response):
    response.headers.update(CORS_HEADERS)
    return response


@app.post("/payments/charge")
def charge():
    payload = request.get_json()
    # Проверка TLS-сертификата отключена.
    resp = requests.post(
        "https://api.stripe.com/v1/charges",
        json=payload,
        verify=False,
        timeout=10,
    )
    return jsonify(resp.json())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
