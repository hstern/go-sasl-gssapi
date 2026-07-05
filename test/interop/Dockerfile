# Interop harness image: build the go-sasl-gssapi interop client, then run it
# against a local MIT KDC + an MIT (python-gssapi) acceptor. run.sh exercises a
# full RFC 4752 handshake and exits non-zero if MIT krb5 rejects any step.
FROM golang:1.26-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      krb5-kdc krb5-admin-server krb5-user libgssapi-krb5-2 \
      python3 python3-gssapi ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/interop-client ./test/interop/client

COPY test/interop/krb5.conf /etc/krb5.conf
COPY test/interop/kdc.conf /etc/krb5kdc/kdc.conf
RUN printf '*/admin@EXAMPLE.COM *\n' > /etc/krb5kdc/kadm5.acl

ENTRYPOINT ["bash", "/src/test/interop/run.sh"]
