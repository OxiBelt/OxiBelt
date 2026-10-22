FROM python:3.15-alpine3.24@sha256:d44b1254cb92329418d164b22b20d86bbd3869d48e80e09e476531a409a728bb

WORKDIR /opt/mock_upstream
RUN mkdir -p /tls

COPY server.py client.py burst_client.py /opt/mock_upstream/

EXPOSE 18080 18443

CMD ["python", "/opt/mock_upstream/server.py"]
