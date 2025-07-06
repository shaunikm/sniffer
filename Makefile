.PHONY: build

.DEFAULT: build

build:
	g++ main.cpp -o main -lpcap
