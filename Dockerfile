FROM gramineproject/gramine:v1.5

RUN apt-get update
RUN apt-get install -y make

ENV SGX 1

RUN gramine-sgx-gen-private-key

WORKDIR /root/

RUN apt-get install -y make

RUN apt-get install -y python3-pip inotify-tools
RUN pip install --upgrade pyopenssl gunicorn flask requests cryptography>=35.0.0 certbot

ADD app.py ./
ADD unicorn.py ./
ADD rsademo.py ./
ADD python.manifest.template ./
ADD Makefile ./
ADD ipfs_cid ./ipfs_cid
ADD run.sh ./

RUN mkdir -p untrustedhost enclave_data

RUN SGX=1 make

ENTRYPOINT []
CMD [ "gramine-sgx-sigstruct-view", "python.sig" ]
