//go:build !disable_pgv
// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/admin/v3/listeners.proto

package adminv3

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

// Validate checks the field values on Listeners with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *Listeners) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Listeners with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in ListenersMultiError, or nil
// if none found.
func (m *Listeners) ValidateAll() error {
	return m.validate(true)
}

func (m *Listeners) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetListenerStatuses() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ListenersValidationError{
						field:  fmt.Sprintf("ListenerStatuses[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ListenersValidationError{
						field:  fmt.Sprintf("ListenerStatuses[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ListenersValidationError{
					field:  fmt.Sprintf("ListenerStatuses[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return ListenersMultiError(errors)
	}

	return nil
}

// ListenersMultiError is an error wrapping multiple validation errors returned
// by Listeners.ValidateAll() if the designated constraints aren't met.
type ListenersMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ListenersMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ListenersMultiError) AllErrors() []error { return m }

// ListenersValidationError is the validation error returned by
// Listeners.Validate if the designated constraints aren't met.
type ListenersValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListenersValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListenersValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListenersValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListenersValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListenersValidationError) ErrorName() string { return "ListenersValidationError" }

// Error satisfies the builtin error interface
func (e ListenersValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListeners.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListenersValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListenersValidationError{}

// Validate checks the field values on ListenerStatus with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *ListenerStatus) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on ListenerStatus with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in ListenerStatusMultiError,
// or nil if none found.
func (m *ListenerStatus) ValidateAll() error {
	return m.validate(true)
}

func (m *ListenerStatus) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Name

	if all {
		switch v := interface{}(m.GetLocalAddress()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, ListenerStatusValidationError{
					field:  "LocalAddress",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, ListenerStatusValidationError{
					field:  "LocalAddress",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetLocalAddress()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ListenerStatusValidationError{
				field:  "LocalAddress",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	for idx, item := range m.GetAdditionalLocalAddresses() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, ListenerStatusValidationError{
						field:  fmt.Sprintf("AdditionalLocalAddresses[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, ListenerStatusValidationError{
						field:  fmt.Sprintf("AdditionalLocalAddresses[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ListenerStatusValidationError{
					field:  fmt.Sprintf("AdditionalLocalAddresses[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return ListenerStatusMultiError(errors)
	}

	return nil
}

// ListenerStatusMultiError is an error wrapping multiple validation errors
// returned by ListenerStatus.ValidateAll() if the designated constraints
// aren't met.
type ListenerStatusMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m ListenerStatusMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m ListenerStatusMultiError) AllErrors() []error { return m }

// ListenerStatusValidationError is the validation error returned by
// ListenerStatus.Validate if the designated constraints aren't met.
type ListenerStatusValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListenerStatusValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListenerStatusValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListenerStatusValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListenerStatusValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListenerStatusValidationError) ErrorName() string { return "ListenerStatusValidationError" }

// Error satisfies the builtin error interface
func (e ListenerStatusValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListenerStatus.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListenerStatusValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListenerStatusValidationError{}
