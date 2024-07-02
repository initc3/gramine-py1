rm -f enclave_data/* untrustedhost/*
touch untrustedhost/request.csr
{
    inotifywait -q -e close_write untrustedhost/request.csr
    certbot certonly --standalone \
	    --preferred-challenges http --http-01-port 8082 \
	    --csr untrustedhost/request.csr \
        --agree-tos \
        --no-eff-email \
	    --fullchain-path untrustedhost/certificate.pem \
	    --non-interactive \
        --email pradyumna.shome@gmail.com \
	    --config-dir certbot --work-dir certbot --logs-dir certbot
} &
export DOMAIN=itemc.ln.soc1024.com
export BOOTSTRAP_MODE=True
gramine-sgx python
