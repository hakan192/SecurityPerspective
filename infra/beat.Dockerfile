FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend /app
ENV PYTHONPATH=/app
CMD ["celery", "-A", "app.tasks.celery_app", "beat", "--loglevel=info"]
