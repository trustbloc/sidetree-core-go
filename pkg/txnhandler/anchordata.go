/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package txnhandler

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const delimiter = "."
const allowedParts = 2

// nolint:gochecknoglobals
var (
	integerRegex = regexp.MustCompile(`^[1-9]\d*$`)
)

// AnchorData holds anchored data
type AnchorData struct {
	NumberOfOperations int
	AnchorAddress      string
}

// ParseAnchorData will parse anchor string into anchor data model
func ParseAnchorData(data string) (*AnchorData, error) {
	parts := strings.Split(data, delimiter)

	if len(parts) != allowedParts {
		return nil, fmt.Errorf("parse anchor data[%s] failed: expecting [%d] parts, got [%d] parts", data, allowedParts, len(parts))
	}

	ok := integerRegex.MatchString(parts[0])
	if !ok {
		return nil, fmt.Errorf("parse anchor data[%s] failed: number of operations must be positive integer", data)
	}

	opsNum, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("parse anchor data[%s] failed: %s", data, err.Error())
	}

	return &AnchorData{
		NumberOfOperations: opsNum,
		AnchorAddress:      parts[1]}, nil
}

// GetAnchorString will create anchor string from anchor data
func (ad *AnchorData) GetAnchorString() string {
	return fmt.Sprintf("%d", ad.NumberOfOperations) + delimiter + ad.AnchorAddress
}
