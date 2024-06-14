from http.server import BaseHTTPRequestHandler, HTTPServer
from ipfs_cid import cid_sha256_unwrap_digest
import requests
from hashlib import sha256
import argparse

class IPFSRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/ipfs/'):
            ipfs_hash = self.path[6:]
            try:
                hash_bytes = cid_sha256_unwrap_digest(ipfs_hash)
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Error parsing IPFS CID. Make sure it's a v1 that uses SHA-256.")
                return
            url = f"{gateway}/ipfs/{ipfs_hash}"
            print(url)
            try:
                response = requests.get(url, timeout=3)
            except requests.exceptions.ReadTimeout:
                self.send_response(504)
                self.end_headers()
                self.wfile.write(f"Error fetching {ipfs_hash}: gateway timeout (possibly not found)".encode())
                return
            if response.status_code == 200:
                if sha256(response.content).digest() == hash_bytes:
                    self.send_response(200)
                    self.send_header('Content-Type', response.headers['Content-Type'])
                    self.end_headers()
                    self.wfile.write(response.content)
                    return
                else:
                    self.send_response(502)
                    self.end_headers()
                    self.wfile.write(f"Error fetching {ipfs_hash}: incorrect response from gateway!".encode())
                    return
            else:
                self.send_response(response.status_code)
                self.end_headers()
                self.wfile.write(f"Error fetching IPFS hash: {response.status_code}".encode())
                return
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5100, help='Port to run the server on')
    parser.add_argument('--gateway', default='https://ipfs.io', help='Upstream gateway to use')
    args = parser.parse_args()
    gateway = args.gateway
    server_address = ('', args.port)
    httpd = HTTPServer(server_address, IPFSRequestHandler)
    print(f"Starting server on port {args.port}...")
    httpd.serve_forever()
