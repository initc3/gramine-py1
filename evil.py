from flask import Flask
import argparse

# A server that returns an incorrect response for a particular IPFS hash
app = Flask(__name__)

@app.route('/ipfs/<string:ipfs_hash>')
def handle_ipfs_request(ipfs_hash):
    if ipfs_hash == 'bafkreibrl5n5w5wqpdcdxcwaazheualemevr7ttxzbutiw74stdvrfhn2m':
        return 'Hello mate, I\'m an evil gateway'
    else:
        return 'Unknown IPFS hash', 404

@app.route('/')
def home():
    return ('Try <a href="/ipfs/bafkreibrl5n5w5wqpdcdxcwaazheualemevr7ttxzbutiw74stdvrfhn2m">'
        '/ipfs/bafkreibrl5n5w5wqpdcdxcwaazheualemevr7ttxzbutiw74stdvrfhn2m</a>');

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=3517, help='Port to run the server on')
    args = parser.parse_args()
    app.run(debug=False, port=args.port)
