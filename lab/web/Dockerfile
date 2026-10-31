# lab-web: the fictional company's web server (nginx) plus labd, which applies the rendered state
# and runs the decoy listeners. Same base as the engine's test target, pinned by digest.
FROM nginx:stable-alpine@sha256:0d3b80406a13a767339fbe2f41406d6c7da727ab89cf8fae399e81f780f814d1

RUN apk add --no-cache python3 openssl \
 && rm -f /etc/nginx/conf.d/default.conf

COPY entrypoint.sh /usr/local/bin/lab-entrypoint
COPY labd.py /usr/local/bin/labd.py
RUN chmod 0755 /usr/local/bin/lab-entrypoint /usr/local/bin/labd.py

ENTRYPOINT ["/usr/local/bin/lab-entrypoint"]
