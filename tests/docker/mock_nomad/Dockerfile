FROM python:3.14-alpine3.24

WORKDIR /opt/mock_nomad

COPY server.py /opt/mock_nomad/

EXPOSE 18091

CMD ["python", "/opt/mock_nomad/server.py"]
