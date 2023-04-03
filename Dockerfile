FROM python:3.10

RUN apt-get update && apt-get install

ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/code

WORKDIR ${PYTHONPATH}

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY /src /code

CMD bash -c "flask db upgrade && gunicorn --worker-class gevent \
  --workers $service_workers \
  --bind 0.0.0.0:$service_port \
  app:app"