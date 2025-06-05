all: build install

build:
	@echo "Building..."
	go build -o bin/mcplocker cmd/cli/main.go

install: build
	@echo "Installing..."
	@cp bin/mcplocker $(HOME)/bin/mcplocker
	@echo "mcplocker installed to $(HOME)/bin"

sudo:
	sudo cp bin/mcplocker /usr/local/bin/mcplocker