FROM python:3.14-alpine3.24

WORKDIR /opt/mock_kubernetes

COPY server.py /opt/mock_kubernetes/

EXPOSE 18090

CMD ["python", "/opt/mock_kubernetes/server.py"]
