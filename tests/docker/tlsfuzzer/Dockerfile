FROM python:3.14-alpine3.24@sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01

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
