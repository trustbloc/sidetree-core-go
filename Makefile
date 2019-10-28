#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# Supported Targets:
#
#   all (default) : runs code checks and unit tests
#   checks: runs code checks (license, spelling, lint)
#   unit-test: runs unit tests


GO_CMD ?= go
export GO111MODULE=on

# Controller API entry point to be used for generating Open API specifications
OPENAPI_SPEC_META=pkg/restapi/diddochandler/doc.go
OPENAPI_DOCKER_IMG=quay.io/goswagger/swagger
# TODO: Switched to dev since release version doesn't support go 1.13
OPENAPI_DOCKER_IMG_VERSION=dev

checks: license lint

license:
	@scripts/check_license.sh

lint:
	@scripts/check_lint.sh

unit-test:
	@scripts/unit.sh

.PHONY: generate-openapi-spec
generate-openapi-spec:
	@echo "Generating and validating controller API specifications using Open API"
	@mkdir -p .build/rest/openapi/spec
	@SPEC_META=$(OPENAPI_SPEC_META) SPEC_LOC=.build/rest/openapi/spec  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh

.PHONY: clean
clean:
	rm -rf .build

all: clean checks unit-test generate-openapi-spec





