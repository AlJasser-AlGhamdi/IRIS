#!/bin/sh
# lab-web start: issue a lab CA and a leaf for wahat-alramal.test inside the container (the private
# keys never exist anywhere else), then hand over to labd, which starts nginx and the decoys.
set -eu

TLS=/etc/nginx/tls
mkdir -p "$TLS" /srv/site
if [ ! -s "$TLS/chain.crt" ] || [ ! -s "$TLS/leaf.key" ]; then
  cd "$TLS"
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
    -keyout ca.key -out ca.crt -subj "/O=Wahat Alramal Lab/CN=Wahat Alramal Lab Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:3072 -sha256 -nodes -keyout leaf.key -out leaf.csr \
    -subj "/O=Wahat Alramal Trading Est./CN=wahat-alramal.test" 2>/dev/null
  printf '%s\n' \
    'subjectAltName=DNS:wahat-alramal.test,DNS:www.wahat-alramal.test' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' > leaf.ext
  openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days 365 \
    -extfile leaf.ext -out leaf.crt 2>/dev/null
  cat leaf.crt ca.crt > chain.crt
  # The CA key has issued its one certificate; it is not kept.
  rm -f ca.key ca.srl leaf.csr leaf.ext
  chmod 600 leaf.key
fi

exec python3 /usr/local/bin/labd.py
