FROM python:3.15-alpine3.24@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211

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
