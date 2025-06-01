# syntax=docker/dockerfile:1
FROM golang:1.24-alpine

ARG X_COMMIT_SHA
ARG BUILD_ENV
ENV COMMIT_SHA=$X_COMMIT_SHA
ENV BUILD_ENV=$BUILD_ENV

VOLUME /app
WORKDIR /app

COPY go.* ./
RUN go mod download

RUN go install github.com/air-verse/air@latest

EXPOSE 4781