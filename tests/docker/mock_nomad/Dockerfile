FROM python:3.14-alpine3.24@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

WORKDIR /opt/mock_nomad

COPY server.py /opt/mock_nomad/

EXPOSE 18091

CMD ["python", "/opt/mock_nomad/server.py"]
