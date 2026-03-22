FROM python:3.12-slim
WORKDIR /server 

RUN apt-get update && apt-get install -y git cron && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt


COPY server.py ./server.py
COPY quark_analysis.py ./quark_analysis.py
COPY virustotal.py ./virustotal.py
COPY virustotal-api-key ./virustotal-api-key
COPY certs/cert.pem ./certs/cert.pem
COPY certs/key.pem ./certs/key.pem

RUN git clone https://github.com/quark-engine/quark-rules ./quark-rules

COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

EXPOSE 8000

CMD ["./entrypoint.sh"]