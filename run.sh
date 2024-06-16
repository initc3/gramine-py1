rm -f enclave_data/* untrustedhost/*
touch untrustedhost/request.csr
{
    inotifywait -q -e close_write untrustedhost/request.csr
    certbot certonly --standalone \
	    --preferred-challenges http --http-01-port 8082 \
	    --csr untrustedhost/request.csr \
	    --fullchain-path untrustedhost/certificate.pem \
	    --non-interactive --agree-tos -m soc1024@illinois.edu \
	    --config-dir certbot --work-dir certbot --logs-dir certbot
} &
gramine-sgx python
