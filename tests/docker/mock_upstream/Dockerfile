FROM python:3.14-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

WORKDIR /opt/mock_upstream
RUN mkdir -p /tls

COPY server.py client.py burst_client.py /opt/mock_upstream/

EXPOSE 18080 18443

CMD ["python", "/opt/mock_upstream/server.py"]
