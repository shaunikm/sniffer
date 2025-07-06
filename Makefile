.PHONY: build

.DEFAULT: build

build:
	gcc main.cpp -o main -lpcap
