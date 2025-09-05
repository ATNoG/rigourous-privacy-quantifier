.PHONY: all build run

all: dev

dev:
	. venv/bin/activate && python3 main.py

build:
	sudo docker build --network=host -t pq .

run:
	sudo docker run --network=host pq
