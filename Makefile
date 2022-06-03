.PHONY: build
build:
	mkdir -p ./dist
	go build -o ./dist/jwt-creator
