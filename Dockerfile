# Small, official Python base image — keeps the final image lean.
FROM python:3.11-slim

# Create a non-root user to run the app — avoids running as root inside the container.
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

WORKDIR /app

# Copy only requirements first so Docker can cache this layer —
# rebuilds are much faster if only your code changes, not dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Now copy the actual application code.
COPY sentinel/ ./sentinel/

# Reports get written here at runtime — create it and hand ownership to the non-root user.
RUN mkdir -p /app/reports && chown -R sentinel:sentinel /app

USER sentinel

ENTRYPOINT ["python", "-m", "sentinel.cli"]
CMD ["--help"]