FROM python:3.14-alpine3.24@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

WORKDIR /opt/mock_dns

COPY server.py /opt/mock_dns/

EXPOSE 53/udp

CMD ["python", "/opt/mock_dns/server.py"]
