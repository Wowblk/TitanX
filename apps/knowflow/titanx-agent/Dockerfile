FROM python:3.12-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY titanx-agent/ ./
RUN pip install --no-cache-dir .

EXPOSE 3000
CMD ["python", "run_gateway.py"]

