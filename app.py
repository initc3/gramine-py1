import ssl
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipfs_cid import cid_sha256_unwrap_digest
import requests
from hashlib import sha256
import argparse
import json
import base64
import os
import time
import socket

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PRIVATE_KEY_PATH = "data/private_key.pem"
CERTIFICATE_PATH = "untrustedhost/certificate.pem"
DOMAIN_NAME=None

# Generate a public/private key pair
#client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#client_public_key = client_private_key.public_key()

def verify_mrenclave(mrenclave):
    # Placeholder function to verify MRENCLAVE using SGX DCAP
    # This should be implemented properly in a production environment
    return True

def encrypt_private_key(shared_key, certificate_private_key):
    # Encrypt the private key with the shared key (symmetric encryption)
    # This is a placeholder for encryption logic
    return certificate_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def read_certificate():
    with open("certificate.pem", "r") as f:
        return f.read()

class IPFSRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(open('templates/index.html','rb').read())
            return

        if self.path.startswith('/ipfs/'):
            ipfs_hash = self.path[6:]
            try:
                hash_bytes = cid_sha256_unwrap_digest(ipfs_hash)
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Error parsing IPFS CID. Make sure it's a v1 that uses SHA-256.")
                return
            url = f"{args.gateway}/ipfs/{ipfs_hash}"
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

    def do_POST(self):
        if self.path == '/bootstrap/':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)

            client_public_key = data['public_key']
            client_mrenclave = data['MRENCLAVE']

            # Verify the MRENCLAVE using SGX DCAP (not implemented in this example)
            if verify_mrenclave(client_mrenclave):
                # Perform Diffie-Hellman exchange
                encrypted_private_key = encrypt_private_key(certificate_private_key, client_public_key)

                response = {
                    'public_key': base64.b64encode(certificate_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)).decode('utf-8'),
                    'certificate': read_certificate(),
                    'encrypted_private_key': base64.b64encode(encrypted_private_key).decode('utf-8')
                }

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
            else:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b'Forbidden: MRENCLAVE verification failed')

def generate_keys_and_csr():
    print("[Bootstrap] Init")
    # Generate a private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Generate a public key
    public_key = private_key.public_key()

    # Write private key to a file

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        print(f"[Bootstrap] Stored private key in {PRIVATE_KEY_PATH}")
        # print(f"[Bootstrap] Private key: {private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())}")

    # Write public key to a file
    public_key_path = "untrustedhost/public_key.pem"
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print(f"[Bootstrap] Stored private key in {public_key_path}")
        # print(f"[Bootstrap] Public key: {public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")

    DOMAIN_NAME = u"item4.ln.soc1024.com"
    # Create a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN_NAME)
    ])).sign(private_key, hashes.SHA256(), backend=default_backend())

    csr_path = "untrustedhost/request.csr"
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
        print(f"[Bootstrap] Stored CSR in {csr_path}")
        # print(f"[Bootstrap] CSR: {csr.public_bytes(encoding=serialization.Encoding.PEM)}")

    # Use certbot to obtain a certificate
    while not os.path.isfile(CERTIFICATE_PATH):
        print('waiting for certificate.pem...')
        time.sleep(1)
    time.sleep(0.2)

    certificate = None
    with open(CERTIFICATE_PATH, "rb") as f:
        certificate = f.read()

    print("[Bootstrap] Certificate: ", certificate)
    print("[Bootstrap] Done")
    return private_key, public_key, CERTIFICATE_PATH

def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048)

def generate_dh_private_key(parameters):
    return parameters.generate_private_key()

def derive_shared_key(client_private_key, server_public_key):
    shared_key = client_private_key.exchange(server_public_key)
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key

def decrypt_private_key(encrypted_private_key, shared_key):
    # Assuming the encrypted private key uses AES-GCM for symmetric encryption
    # This part should match the actual encryption method used by the server
    nonce = encrypted_private_key[:12]  # First 12 bytes are the nonce
    tag = encrypted_private_key[-16:]  # Last 16 bytes are the tag
    ciphertext = encrypted_private_key[12:-16]  # Remainder is the ciphertext

    decryptor = Cipher(
        algorithms.AES(shared_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()

    decrypted_private_key = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_private_key

def init_bootstrap(url: str):
    # Generate a public/private key pair for the client
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    client_public_key = client_private_key.public_key()

    # Generate MRENCLAVE (this is a placeholder and should be replaced with actual SGX MRENCLAVE value)
    mrenclave = "dummy_mrenclave_value"

    # Serialize the client's public key
    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Create a JSON payload
    payload = {
        'public_key': client_public_key_pem,
        'MRENCLAVE': mrenclave
    }

    # Send a POST request to the given URL
    response = requests.post(url + '/bootstrap/', json=payload)

    if response.status_code == 200:
        response_data = response.json()
        server_public_key_pem = response_data['public_key']
        certificate_pem = response_data['certificate']
        encrypted_private_key = base64.b64decode(response_data['encrypted_private_key'])

        # Deserialize the server's public key
        server_public_key = serialization.load_pem_public_key(server_public_key_pem.encode('utf-8'))

        # Perform Diffie-Hellman key exchange to derive the shared key
        parameters = generate_dh_parameters()
        client_dh_private_key = generate_dh_private_key(parameters)
        shared_key = derive_shared_key(client_dh_private_key, server_public_key)

        # Decrypt the private key using the shared key
        decrypted_private_key = decrypt_private_key(encrypted_private_key, shared_key)

        print("Received server public key, certificate, and decrypted private key.")
        print(f"Server Public Key: {server_public_key_pem}")
        print(f"Certificate: {certificate_pem}")
        print(f"Decrypted Private Key: {decrypted_private_key.decode('utf-8')}")

    else:
        print(f"Failed to bootstrap: {response.status_code} - {response.text}")

def perform_diffie_hellman(client_public_key_pem):
    # Deserialize client's public key
    client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'))

    # Generate server's DH private key
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    server_private_key = parameters.generate_private_key()

    # Perform the key exchange
    shared_key = server_private_key.exchange(client_public_key)

    # Derive a symmetric key from the shared key
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)

    return derived_key

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8083, help='Port to run the server on')
    parser.add_argument('--gateway', default='https://ipfs.io', help='Upstream gateway to use')
    parser.add_argument('--domain', required=True, help='Domain this node will serve on')
    # Add the bootstrap_mode argument
    parser.add_argument('--bootstrap_mode', action='store_true', help='Generate public and private keys if set')
    parser.add_argument('--bootstrap_link', type=str, help='Link to boostrap node, if not bootstrapping.')

    args = parser.parse_args()

    DOMAIN_NAME=args.domain

    has_bootstrapped = False

    # Check if bootstrap_mode is set to True
    if args.bootstrap_mode:
        certificate_private_key, certificate_public_key, certificate = generate_keys_and_csr()
        print("Public and private keys generated.")
        has_bootstrapped = True
    elif True:
        # Connect to a bootstrapping enclave
        print("Bootstrap mode is not enabled.")
        print("Node must bootstrap before serving HTTP.")
        print(f"Initiating bootstrap with {args.bootstrap_link}")
        certificate_private_key, certificate_public_key, certificate = init_bootstrap(args.bootstrap_link)
    else:
        pass

    # Blast past a failure... without it this fails in gramine
    # when calling ssl.wrap_socket
    ssl.SSLSocket.getpeername = lambda _: None

    # Create an HTTP server with the SSL-wrapped socket
    httpd = HTTPServer(('0.0.0.0', args.port), IPFSRequestHandler)
    if True:
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                   certfile=CERTIFICATE_PATH,
                                   keyfile=PRIVATE_KEY_PATH,
                                   server_side=True,
                                   do_handshake_on_connect=False)

    print(f"Starting server on port {args.port}...")
    httpd.serve_forever()
