# Slim Python base = small image, fast to build.
FROM python:3.12-slim

# All app files live under /app inside the container.
WORKDIR /app

# Copy ONLY requirements first. Docker caches this layer, so as long as
# requirements.txt doesn't change, `pip install` is not re-run on every code edit.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Now copy the application code.
COPY router.py .

# Document the port the app listens on (matches LISTEN_PORT in docker-compose).
EXPOSE 5000

# Start the Flask security router.
CMD ["python", "router.py"]
