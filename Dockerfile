FROM gramineproject/gramine:v1.5

RUN apt-get update
RUN apt-get install -y make python3-requests

ENV SGX 1

RUN gramine-sgx-gen-private-key

WORKDIR /root/

ADD app.py ./
ADD ipfs_cid ./ipfs_cid
ADD python.manifest.template ./
ADD Makefile ./

RUN mkdir -p untrustedhost

RUN SGX=1 make

EXPOSE 5100

ENTRYPOINT []
CMD [ "gramine-sgx-sigstruct-view", "python.sig" ]
