from flask import Flask, request, Response
from ipfs_cid import cid_sha256_unwrap_digest
import requests
from hashlib import sha256
import argparse

app = Flask(__name__)
gateway = "https://ipfs.io"

@app.route('/ipfs/<string:ipfs_hash>')
def handle_ipfs_request(ipfs_hash):
    try:
        hash_bytes = cid_sha256_unwrap_digest(ipfs_hash)
    except Exception as e:
        return "Error parsing IPFS CID. Make sure it's a v1 that uses SHA-256.", 400
    url = f"{gateway}/ipfs/{ipfs_hash}"
    response = requests.get(url)
    if response.status_code == 200:
        if sha256(response.content).digest() == hash_bytes:
            response = Response(response.content, mimetype=response.headers['Content-Type'])
            return response
        else:
            return f"Error fetching {ipfs_hash}: incorrect response from gateway!", 502
    else:
        return f"Error fetching IPFS hash: {response.status_code}", response.status_code

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000, help='Port to run the server on')
    args = parser.parse_args()
    app.run(debug=True, port=args.port)
