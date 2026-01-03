FROM docker:27-cli

RUN apk add --no-cache python3

WORKDIR /opt/blackcat-operator
RUN mkdir -p /opt/blackcat-operator/compose /opt/blackcat-operator/shared

COPY docker-compose*.yml /opt/blackcat-operator/compose/
COPY operator/server.py /opt/blackcat-operator/server.py

EXPOSE 8090
ENTRYPOINT ["python3", "-u", "/opt/blackcat-operator/server.py"]
