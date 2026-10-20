FROM python:3.14-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

WORKDIR /opt/mock_dns

COPY server.py /opt/mock_dns/

EXPOSE 53/udp

CMD ["python", "/opt/mock_dns/server.py"]
