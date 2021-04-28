FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y softhsm2 python3 python3-pip gnutls-bin git vim

COPY . /app
WORKDIR /app

RUN pip3 install poetry
RUN poetry install
RUN softhsm2-util --init-token --slot 0 --label "token" --so-pin 1234 --pin 1234
RUN poetry run pytest tests
RUN poetry run python tests/functional/create_key.py

ENTRYPOINT ["poetry"]

CMD ["run", "python", "tests/functional/functional_test.py"]
