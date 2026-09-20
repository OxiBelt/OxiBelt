FROM python:3.14-alpine3.24@sha256:016508ba505da24f7139765bc4bb669df4e88eb2f12eeadd571bf2f88d7533df

WORKDIR /opt/mock_external_cache
COPY server.py /opt/mock_external_cache/server.py

EXPOSE 18081
CMD ["python", "/opt/mock_external_cache/server.py"]
