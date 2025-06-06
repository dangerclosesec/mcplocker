# syntax=docker/dockerfile:1
FROM golang:1.24-alpine

ARG X_COMMIT_SHA
ARG BUILD_ENV
ENV COMMIT_SHA=$X_COMMIT_SHA
ENV BUILD_ENV=$BUILD_ENV
ENV CONTAINER=true

VOLUME /app
WORKDIR /app

COPY go.* ./
RUN go mod download

COPY . .

RUN go mod tidy
RUN go build -o /app/bin/authserver ./cmd/authserver/main.go

# Conditionally install air only for development builds
RUN if [ "$BUILD_ENV" = "dev" ]; then go install github.com/air-verse/air@latest; fi

CMD ["/app/bin/authserver"]

EXPOSE 38741