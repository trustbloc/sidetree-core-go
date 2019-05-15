#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

GOLANGCI_LINT_CMD=golangci-lint

PWD=`pwd`
echo "Running golangci-lint :: pwd" $PWD

$GOLANGCI_LINT_CMD run -c "$GOPATH/src/github.com/trustbloc/sidetree-core-go/.golangci.yml"

echo "golangci-lint finished successfully :: pwd" $PWD