FROM python:3.12-slim
COPY lab/ /app/
# Only root (the lab services) can read the lab code: a shell obtained on the target runs as nobody.
RUN chmod -R go-rwx /app
WORKDIR /app
