FROM  python:3.12-slim
LABEL maintainer="adam.dobrawy{at}siecobywatelska.pl"

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=mock.py

CMD [ "flask" , "run", "-h", "0.0.0.0" ]
