FROM python:3

WORKDIR /usr/src

COPY . /usr/src

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

#CMD [ "python", "run.py" ]

ENV FLASK_APP run
ENV FLASK_DEBUG=1
CMD ["flask", "run", "-h", "0.0.0.0", "--port", "25201"]
