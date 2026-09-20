FROM python:3.14-alpine3.24@sha256:016508ba505da24f7139765bc4bb669df4e88eb2f12eeadd571bf2f88d7533df

WORKDIR /opt/mock_upstream
RUN mkdir -p /tls

COPY server.py client.py burst_client.py /opt/mock_upstream/

EXPOSE 18080 18443

CMD ["python", "/opt/mock_upstream/server.py"]
