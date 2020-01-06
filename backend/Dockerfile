FROM python3.7-alpine

LABEL maintainer="Kunal Malhotra, kunal.malhotra3@ibm.com"

COPY . /app

WORKDIR /app

RUN pip install -r requirements.txt

CMD ["gunicorn","-w 4", "__init__:app"]
