FROM python:3.14-alpine3.24

WORKDIR /opt/mock_upstream
RUN mkdir -p /tls

COPY server.py client.py /opt/mock_upstream/

EXPOSE 18080 18443

CMD ["python", "/opt/mock_upstream/server.py"]
