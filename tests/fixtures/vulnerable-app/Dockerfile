FROM python:3.8

WORKDIR /app

ADD ./setup.sh /app/setup.sh

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV AWS_SECRET_ACCESS_KEY=AKIAZ3X9K2M4NQPLW8RT

EXPOSE 5000

CMD ["python", "app/main.py"]
