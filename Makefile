build:
	@go build -o bin/bank-json-apis-golang

run: build
	@./bin/bank-json-apis-golang

test:
	@go test -v ./...