all: build install

build:
	@echo "Building..."
	go build -o bin/mcplocker cmd/cli/main.go

install: build
	@echo "Installing..."
	@cp bin/mcplocker $(HOME)/bin/mcplocker
	@echo "mcplocker installed to $(HOME)/bin"

sudo: build
	sudo cp bin/mcplocker /usr/local/bin/mcplocker

docker:
	@echo "Building Docker image..."
	docker build --build-arg BUILD_ENV=prod -t mcplocker-authserver:latest -f Dockerfile .

docker-dev:
	@echo "Building development Docker image..."
	docker build --build-arg BUILD_ENV=dev -t mcplocker-authserver:dev -f Dockerfile .

web: docker-dev
	docker run -p38741:38741 -v $(PWD)/:/app -it mcplocker-authserver:dev \
		air -build.bin /app/bin/mcplocker \
		-build.cmd="go build -o /app/bin/mcplocker cmd/authserver/main.go"