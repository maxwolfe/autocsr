from ubuntu:20.04

run apt-get update
run apt-get install -y softhsm2 python3 python3-pip gnutls-bin git vim curl

copy . /app
workdir /app

run pip3 install poetry
run poetry install
run softhsm2-util --init-token --slot 0 --label "token" --so-pin 1234 --pin 1234 
run poetry run pytest
run poetry run python create_key.py

entrypoint ["/bin/sh"]

cmd ["python3"]
