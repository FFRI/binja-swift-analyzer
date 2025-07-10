all: main

main: main.swift
	swiftc -O main.swift -o main
	cp main main_stripped
	strip main_stripped

clean:
	rm -f main
	rm -f main_stripped