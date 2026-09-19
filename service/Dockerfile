FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY biedronka_cli.py shakeomat_notify.py .

ENV BIEDRONKA_HOME=/app/data

CMD ["python3", "shakeomat_notify.py"]
