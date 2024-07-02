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
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PRIVATE_KEY_PATH = "data/private_key.pem"
CERTIFICATE_PATH = "untrustedhost/certificate.pem"
DOMAIN_NAME=None

# Diffie-Hellman parameters (normally these would be agreed upon beforehand)
DIFFIE_HELLMAN_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DIFFIE_HELLMAN_G = 2

certificate_private_key = None

import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
import nacl.encoding

# Generate private and public keys
def generate_keypair():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

# Encrypt a message
def encrypt_message(recipient_public_key, message):
    # Generate a random nonce
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    # Create a Box with the public key and a new random private key
    ephemeral_private_key = PrivateKey.generate()
    box = Box(ephemeral_private_key, recipient_public_key)

    # Encrypt the message with the nonce
    encrypted_message = box.encrypt(message, nonce)

    # Return the ephemeral public key and the encrypted message
    return ephemeral_private_key.public_key, encrypted_message

# Decrypt a message
def decrypt_message(recipient_private_key, ephemeral_public_key, encrypted_message):
    # Create a Box with the private key and the ephemeral public key
    box = Box(recipient_private_key, ephemeral_public_key)

    # Decrypt the message
    decrypted_message = box.decrypt(encrypted_message)

    return decrypted_message

def encrypt_private_key(certificate_private_key, client_public_key_pem):
    certificate_private_key = base64.b64(certificate_private_key)
    client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode('utf-8'), backend=default_backend())
    return encrypt_message(client_public_key, certificate_private_key)

# Function to decrypt the encrypted private key with the client private key
def decrypt_private_key(encrypted_key_base64, client_private_key, ephemeral_public_key):
    encrypted_key = base64.b64decode(encrypted_key_base64)

    return serialization.load_pem_private_key(decrypted_key, password=None, backend=default_backend())

def verify_mrenclave(mrenclave):
    # Placeholder function to verify MRENCLAVE using SGX DCAP
    # This should be implemented properly in a production environment
    return True

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

            client_public_key = PublicKey(data['public_key'].encode('utf-8'), encoder=nacl.encoding.Base64Encoder)
            client_mrenclave = data['MRENCLAVE']

            # Verify the MRENCLAVE using SGX DCAP (not implemented in this example)
            if verify_mrenclave(client_mrenclave):
                # Perform Diffie-Hellman exchange
                ephemeral_public_key, encrypted_private_key = encrypt_message(certificate_private_key, client_public_key)

                response = {
                    'public_key': base64.b64encode(certificate_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)).decode('utf-8'),
                    'certificate': read_certificate(),
                    'encrypted_private_key': base64.b64encode(encrypted_private_key).decode('utf-8'),
                    'ephemeral_public_key': ephemeral_public_key.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8')
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

def init_bootstrap(url: str, session):
    # Generate a public/private key pair for the client
    client_private_key, client_public_key = generate_keypair()

    # Generate MRENCLAVE (this is a placeholder and should be replaced with actual SGX MRENCLAVE value)
    mrenclave = "dummy_mrenclave_value"

    # Create a JSON payload
    payload = {
        'public_key': client_public_key.encode(encoder=nacl.encoding.Base64Encoder).decode('utf-8'),
        'MRENCLAVE': mrenclave
    }

    # Send a POST request to the given URL
    response = session.post("https://" + url + '/bootstrap/', json=payload)

    if response.status_code == 200:
        print("Received payload from boostrap server")
        response_data = response.json()
        certificate_pem = response_data['certificate']
        ephemeral_public_key = PublicKey(response_data['ephemeral_public_key'].encode('utf-8'))
        encrypted_certificate_private_key = response_data['encrypted_private_key'].encode('utf-8')

        # Use the client private key to decrypt the certificate private key
        certificate_private_key_str = decrypt_private_key(encrypted_certificate_private_key, client_private_key, ephemeral_public_key)

        # This is not a NaCl data type, but from cryptography
        certificate_private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None,  # No password for demonstration purposes
                backend=default_backend()
        )

        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(certificate_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"[Bootstrap] Stored certificate private key in {PRIVATE_KEY_PATH}")

        with open(CERTIFICATE_PATH, "wb") as f:
            f.write(certificate_pem)
        print(f"[Bootstrap] Stored certificate in {CERTIFICATE_PATH}")

        print("Received server public key, certificate, and decrypted private key.")
        print(f"Certificate: {certificate_pem}")
        # print(f"Decrypted Private Key: {certificate_private_key.decode('utf-8')}")
        return certificate_private_key, certfile

    else:
        print(f"Failed to bootstrap: {response.status_code} - {response.text}")
        return None, None

def get_custom_requests_session():
    import ssl
    import requests

    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.poolmanager import PoolManager
    from requests.packages.urllib3.util import ssl_
    # Create a custom SSL context that only supports TLS 1.3
    ssl_context = ssl.create_default_context()
    ssl_context.options |= ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1

    # Create a custom HTTPAdapter with the TLS 1.3 SSL context
    class TLS13HTTPAdapter(requests.adapters.HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            context = ssl_context
            kwargs['ssl_context'] = context
            return super(TLS13HTTPAdapter, self).init_poolmanager(*args, **kwargs)

    # Create a session and mount the custom adapter
    session = requests.Session()
    adapter = TLS13HTTPAdapter()
    session.mount('https://', adapter)
    return session

if __name__ == '__main__':
    print("Entered server main")
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8089, help='Port to run the server on')
    parser.add_argument('--gateway', default='https://ipfs.io', help='Upstream gateway to use')

    args = parser.parse_args()

    session = get_custom_requests_session()

    has_bootstrapped = False
    
    DOMAIN_NAME = os.getenv('DOMAIN')
    bootstrap_link = os.getenv('BOOTSTRAP_LINK')
    bootstrap_mode = os.getenv('BOOTSTRAP_MODE')
    if bootstrap_mode == "True":
        print("Bootstrap mode")
        certificate_private_key, certificate_public_key, certificate = generate_keys_and_csr()
        print("Public and private keys generated.")
        has_bootstrapped = True
    else:
        # Connect to a bootstrapping enclave
        print("Bootstrap mode is not enabled.")
        print("Node must bootstrap before serving HTTP.")
        print(f"Initiating bootstrap with {bootstrap_link}")
        certificate_private_key, certificate = init_bootstrap(bootstrap_link, session)
        if certificate_private_key:
            has_bootstrapped = True

    # Blast past a failure... without it this fails in gramine
    # when calling ssl.wrap_socket
    ssl.SSLSocket.getpeername = lambda _: None
    print(f"args.port: {args.port}")


    # Create an HTTP server with the SSL-wrapped socket
    httpd = HTTPServer(('0.0.0.0', args.port), IPFSRequestHandler)
    if True:
        httpd.socket = ssl.wrap_socket(httpd.socket,
                                   certfile=CERTIFICATE_PATH,
                                   keyfile=PRIVATE_KEY_PATH,
                                   server_side=True,
                                   ssl_version=ssl.PROTOCOL_TLSv1,
                                   do_handshake_on_connect=True)

    print(f"Starting server on port {args.port}...")
    httpd.serve_forever()
