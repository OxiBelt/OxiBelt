FROM python:3.14-alpine3.24@sha256:016508ba505da24f7139765bc4bb669df4e88eb2f12eeadd571bf2f88d7533df

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
