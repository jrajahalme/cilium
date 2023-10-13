// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/resource_monitors/downstream_connections/v3/downstream_connections.proto

package downstream_connectionsv3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on DownstreamConnectionsConfig with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *DownstreamConnectionsConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on DownstreamConnectionsConfig with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// DownstreamConnectionsConfigMultiError, or nil if none found.
func (m *DownstreamConnectionsConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *DownstreamConnectionsConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if m.GetMaxActiveDownstreamConnections() <= 0 {
		err := DownstreamConnectionsConfigValidationError{
			field:  "MaxActiveDownstreamConnections",
			reason: "value must be greater than 0",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return DownstreamConnectionsConfigMultiError(errors)
	}

	return nil
}

// DownstreamConnectionsConfigMultiError is an error wrapping multiple
// validation errors returned by DownstreamConnectionsConfig.ValidateAll() if
// the designated constraints aren't met.
type DownstreamConnectionsConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m DownstreamConnectionsConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m DownstreamConnectionsConfigMultiError) AllErrors() []error { return m }

// DownstreamConnectionsConfigValidationError is the validation error returned
// by DownstreamConnectionsConfig.Validate if the designated constraints
// aren't met.
type DownstreamConnectionsConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DownstreamConnectionsConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DownstreamConnectionsConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DownstreamConnectionsConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DownstreamConnectionsConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DownstreamConnectionsConfigValidationError) ErrorName() string {
	return "DownstreamConnectionsConfigValidationError"
}

// Error satisfies the builtin error interface
func (e DownstreamConnectionsConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDownstreamConnectionsConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DownstreamConnectionsConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DownstreamConnectionsConfigValidationError{}
