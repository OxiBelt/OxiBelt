FROM python:3.14-alpine3.24@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

WORKDIR /opt/mock_external_cache
COPY server.py /opt/mock_external_cache/server.py

EXPOSE 18081
CMD ["python", "/opt/mock_external_cache/server.py"]
