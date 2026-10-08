FROM python:3.14-alpine3.24@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

WORKDIR /opt/mock_external_cache
COPY server.py /opt/mock_external_cache/server.py

EXPOSE 18081
CMD ["python", "/opt/mock_external_cache/server.py"]
