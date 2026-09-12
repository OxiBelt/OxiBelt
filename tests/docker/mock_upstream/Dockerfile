FROM python:3.14-alpine3.24@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

WORKDIR /opt/mock_upstream
RUN mkdir -p /tls

COPY server.py client.py burst_client.py /opt/mock_upstream/

EXPOSE 18080 18443

CMD ["python", "/opt/mock_upstream/server.py"]
