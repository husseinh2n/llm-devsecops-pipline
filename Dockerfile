FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python -c "from app.main import init_db; init_db()"

EXPOSE 5000

# NOTE: No USER directive — container runs as root (another finding)
CMD ["python", "-m", "app.main"]
