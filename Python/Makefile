ifeq (,$(wildcard ./.env))
	# Make sure that .env exists, even if empty
	touch .env
endif
include .env.example
include .env
export

.DEFAULT_GOAL := run

HTTP_SIGN_PRIVATE_KEY_FULL_FILE_NAME = $(shell readlink -f $(UPVEST_API_HTTP_SIGN_PRIVATE_KEY_FILENAME))

DOCKER_FILE_ENCRYPTION_PARAMS = ""
ifneq (,$(UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY_FILENAME))
	FILE_ENCRYPTION_PRIVATE_KEY_FULL_FILE_NAME = $(shell readlink -f $(UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY_FILENAME))
	DOCKER_FILE_ENCRYPTION_PARAMS = --env UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY_FILENAME=/work/file_encryption_private_key.pem --volume $(FILE_ENCRYPTION_PRIVATE_KEY_FULL_FILE_NAME):/work/file_encryption_private_key.pem
endif

DOCKER ?= docker

HERE = $(shell pwd)
DOCKER_IMAGE_LOCAL_DEV ?= upvest-http-message-signatures-in-python:latest

.PHONY: build
build:
	$(DOCKER) build \
		--file Dockerfile \
		--tag $(DOCKER_IMAGE_LOCAL_DEV) \
		.

.PHONY: run
run: build
	$(DOCKER) run \
		--rm \
		--tty \
		--interactive \
		--env-file .env.example \
		--env-file .env \
		--env UPVEST_API_HTTP_SIGN_PRIVATE_KEY_FILENAME=/work/http_sign_private_key.pem \
		--volume $(HTTP_SIGN_PRIVATE_KEY_FULL_FILE_NAME):/work/http_sign_private_key.pem \
		$(DOCKER_FILE_ENCRYPTION_PARAMS) \
		--volume $(HERE)/.env:/work/.env \
		--volume $(HERE)/.env.example:/work/.env.example \
		--volume $(HERE)/download_mifir_report.py:/work/download_mifir_report.py \
		--volume $(HERE)/main.py:/work/main.py \
		--volume $(HERE)/requirements.txt:/work/requirements.txt \
		--volume $(HERE)/run.sh:/work/run.sh \
		--volume $(HERE)/run_download.sh:/work/run_download.sh \
		--volume $(HERE)/settings.py:/work/settings.py \
		--volume $(HERE)/pkg/upvest_investment_api/src/upvest_investment_api:/work/pkg/upvest_investment_api/src/upvest_investment_api \
		--volume $(HERE)/venv:/work/venv \
		$(DOCKER_IMAGE_LOCAL_DEV)

# You might need to do that when switching between running inside Docker and
# running directly on your machine.
.PHONY: clean
clean:
	rm -rf ./venv/*
