FROM python:3.12-alpine

WORKDIR /opt/mock_kubernetes

COPY server.py /opt/mock_kubernetes/

EXPOSE 18090

CMD ["python", "/opt/mock_kubernetes/server.py"]
