FROM python:3.14-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

# The runner assembles these trees from the exact commits in
# tests/scripts/run-tls13-tlsfuzzer.sh before building this image. No pip or
# mutable package index is involved.
COPY tlsfuzzer /opt/tlsfuzzer
COPY tlslite-ng /opt/tlslite-ng
COPY ecdsa /opt/ecdsa
COPY six /opt/six
COPY h1_close_notify.py /opt/probes/h1_close_notify.py
COPY server.pem /opt/probes/server.pem

ENV PYTHONPATH=/opt/tlsfuzzer:/opt/tlslite-ng:/opt/ecdsa/src:/opt/six \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/tlsfuzzer
ENTRYPOINT ["python"]
