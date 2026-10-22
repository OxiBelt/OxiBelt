FROM python:3.15-alpine3.24@sha256:d44b1254cb92329418d164b22b20d86bbd3869d48e80e09e476531a409a728bb

WORKDIR /opt/mock_nomad

COPY server.py /opt/mock_nomad/

EXPOSE 18091

CMD ["python", "/opt/mock_nomad/server.py"]
