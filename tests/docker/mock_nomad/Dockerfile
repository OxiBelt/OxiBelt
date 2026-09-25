FROM python:3.14-alpine3.24@sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01

WORKDIR /opt/mock_nomad

COPY server.py /opt/mock_nomad/

EXPOSE 18091

CMD ["python", "/opt/mock_nomad/server.py"]
