#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e
GO_CMD="${GO_CMD:-go}"
GOPATH="${GOPATH:-${HOME}/go}"


function installGolangCiLint {
    echo "Installing golangci-lint..."

    declare repo="github.com/golangci/golangci-lint/cmd/golangci-lint"
    declare revision="v1.16.0"
    declare pkg="github.com/golangci/golangci-lint/cmd/golangci-lint"

    installGoPkg "${repo}" "${revision}" "" "golangci-lint"
    cp -f ${BUILD_TMP}/bin/* ${GOPATH}/bin/
    rm -Rf ${GOPATH}/src/${pkg}
    mkdir -p ${GOPATH}/src/${pkg}
    cp -Rf ${BUILD_TMP}/src/${repo}/* ${GOPATH}/src/${pkg}/
}

function installGoPkg {
    declare repo=$1
    declare revision=$2
    declare pkgPath=$3
    shift 3
    declare -a cmds=$@

    echo "Installing ${repo}@${revision} to $GOPATH/bin ..."

    GO111MODULE=off GOBIN=${BUILD_TMP}/bin GOPATH=${BUILD_TMP} go get -d ${repo}
    tag=$(cd ${BUILD_TMP}/src/${repo} && git tag -l | sort -V --reverse | head -n 1 | grep "${revision}" || true)
    if [ ! -z "${tag}" ]; then
        revision=${tag}
        echo "  using tag ${revision}"
    fi
    (cd ${BUILD_TMP}/src/${repo} && git reset --hard ${revision})
    echo " Checking $GOPATH ..."
    GO111MODULE=off GOBIN=${BUILD_TMP}/bin GOPATH=${BUILD_TMP} go install -i ${repo}/${pkgPath}
    mkdir -p ${GOPATH}/bin
    for cmd in ${cmds[@]}
    do
        echo "Copying ${cmd} to ${GOPATH}/bin"
        cp -f ${BUILD_TMP}/bin/${cmd} ${GOPATH}/bin/
    done
}

function installDependencies {
    echo "Installing dependencies ..."
    BUILD_TMP=`mktemp -d 2>/dev/null || mktemp -d -t 'sidetreecorego'`
    installGolangCiLint

    rm -Rf ${BUILD_TMP}
}

installDependencies
