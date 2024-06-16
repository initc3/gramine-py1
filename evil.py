from flask import Flask, Response
import argparse
import requests

# A server that returns an incorrect response for a particular IPFS hash
app = Flask(__name__)

@app.route('/ipfs/<string:ipfs_hash>')
def handle_ipfs_request(ipfs_hash):
    if ipfs_hash == 'bafkreibrl5n5w5wqpdcdxcwaazheualemevr7ttxzbutiw74stdvrfhn2m':
        return 'Hello mate, I\'m an evil gateway'
    else:
        r = requests.get(f'https://ipfs.io/ipfs/{ipfs_hash}')
        return Response(r.content, status=r.status_code, headers=dict(r.headers));

@app.route('/')
def home():
    return ('Try <a href="/ipfs/bafkreibrl5n5w5wqpdcdxcwaazheualemevr7ttxzbutiw74stdvrfhn2m">'
        '/ipfs/bafkreibrl5n5w5wqpdcdxcwaazheualemevr7ttxzbutiw74stdvrfhn2m</a>');

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8011, help='Port to run the server on')
    args = parser.parse_args()
    app.run(debug=False, port=args.port)
