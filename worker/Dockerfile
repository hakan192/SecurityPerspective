FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt /tmp/backend-requirements.txt
RUN pip install --no-cache-dir -r /tmp/backend-requirements.txt
COPY backend/app ./app
COPY worker/worker.py ./worker.py
CMD ["python", "worker.py"]
