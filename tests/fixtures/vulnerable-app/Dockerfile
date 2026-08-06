FROM python:3.8

WORKDIR /app

# ADD with a remote URL instead of COPY + verified download.
ADD https://example.com/setup.sh /app/setup.sh

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Secret baked into an image layer.
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE

EXPOSE 5000

# No USER instruction: the container runs as root.
CMD ["python", "app/main.py"]
