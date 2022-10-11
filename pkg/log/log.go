/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"github.com/trustbloc/sidetree-core-go/pkg/internal/log"
)

// SetLevel sets the log level for given module and level.
func SetLevel(module string, level log.Level) {
	log.SetLevel(module, level)
}

// SetDefaultLevel sets the default log level.
func SetDefaultLevel(level log.Level) {
	log.SetDefaultLevel(level)
}

// GetLevel returns the log level for the given module.
func GetLevel(module string) log.Level {
	return log.GetLevel(module)
}

// SetSpec sets the log levels for individual modules as well as the default log level.
// The format of the spec is as follows:
//
// module1=level1:module2=level2:module3=level3:defaultLevel
//
// Valid log levels are: critical, error, warning, info, debug
//
// Example:
//
// module1=error:module2=debug:module3=warning:info
func SetSpec(spec string) error {
	return log.SetSpec(spec)
}

// GetSpec returns the log spec which specifies the log level of each individual module. The spec is
// in the following format:
//
// module1=level1:module2=level2:module3=level3:defaultLevel
//
// Example:
//
// module1=error:module2=debug:module3=warning:info
func GetSpec() string {
	return log.GetSpec()
}
