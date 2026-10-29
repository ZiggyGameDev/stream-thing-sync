FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY static ./static

# compose overrides this with the host user (so /data on the host stays owned by ziggy);
# this default keeps `docker run` from running as root too.
RUN useradd --system --uid 10001 --no-create-home app
USER app

EXPOSE 8095
# --no-access-log: uvicorn's access log would print query strings (/link?code=...).
# app.py logs method + path + status itself.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8095", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-access-log"]
