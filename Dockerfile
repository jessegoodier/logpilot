# Dockerfile

# Any python should work.
FROM python:3.13-alpine
# Set environment variables to prevent Python from writing .pyc files and to ensure output is flushed
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
# Install system dependencies
# RUN apk add --no-cache \
#     gcc \
#     musl-dev \
#     libffi-dev \
#     python3-dev \
#     && pip install --upgrade pip
# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# --no-cache-dir reduces image size by not storing the pip cache
# --trusted-host pypi.python.org can sometimes help in restricted network environments
RUN pip install --no-cache-dir --trusted-host pypi.python.org --trusted-host files.pythonhosted.org --trusted-host pypi.org -r requirements.txt

# Mount the configmap with the code. Alternatively, copy the rest of the application code (app.py and index.html) into the container at /app
# COPY app.py .
# COPY index.html .
EXPOSE 5001

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "app:app"]
