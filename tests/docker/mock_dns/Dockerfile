FROM python:3.12-alpine3.23

WORKDIR /opt/mock_dns

COPY server.py /opt/mock_dns/

EXPOSE 53/udp

CMD ["python", "/opt/mock_dns/server.py"]
