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

export GOTOOLCHAIN=go1.25.0+auto

GOBIN_PATH=$(abspath .)/build/bin
MOCKGEN=$(GOBIN_PATH)/mockgen
GOMOCKS=pkg/internal/gomocks
MOCK_VERSION 	?=v1.7.0-rc.1

GO_CMD ?= go
export GO111MODULE=on

checks: license #lint

license:
	@scripts/check_license.sh

lint:
	@scripts/check_lint.sh

unit-test:
	@scripts/unit.sh

.PHONY: clean
clean:
	rm -rf .build

all: clean checks unit-test

