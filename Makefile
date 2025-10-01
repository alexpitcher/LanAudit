.PHONY: build run test clean lint build-darwin build-linux vet

build:
	@mkdir -p ./bin
	go build -o ./bin/lanaudit ./cmd/lanaudit

build-darwin:
	@mkdir -p ./bin
	GOOS=darwin GOARCH=amd64 go build -o ./bin/lanaudit_darwin_amd64 ./cmd/lanaudit
	GOOS=darwin GOARCH=arm64 go build -o ./bin/lanaudit_darwin_arm64 ./cmd/lanaudit

build-linux:
	@mkdir -p ./bin
	GOOS=linux GOARCH=amd64 go build -o ./bin/lanaudit_linux_amd64 ./cmd/lanaudit
	GOOS=linux GOARCH=arm64 go build -o ./bin/lanaudit_linux_arm64 ./cmd/lanaudit

run:
	go run ./cmd/lanaudit

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@echo "Linting complete"

clean:
	rm -rf ./bin
	rm -f coverage.txt coverage.html *.out
