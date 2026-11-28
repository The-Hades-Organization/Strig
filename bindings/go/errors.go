package strig

import (
	"errors"
	"fmt"
)

// Error is a failure reported by the engine. Code is the stable errorCode of the JavaScript
// binding (INVALID_INPUT, UNKNOWN_SUBJECT, DSL_PARSE, ...); Message is for people.
type Error struct {
	Code        string
	Message     string
	Diagnostics []any
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// Is lets errors.Is match two *Error by Code.
func (e *Error) Is(target error) bool {
	var other *Error
	return errors.As(target, &other) && other.Code == e.Code
}

// CodeOf returns the Code of the *Error in err's chain, or "" when there is none.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// ErrClosed is returned by a call on an Engine or Context that was already closed.
var ErrClosed = &Error{Code: "INVALID_ARGUMENT", Message: "engine or context is closed"}

// ErrBroken is returned once the module trapped: the instance is discarded and every later call
// fails closed instead of answering from a state that can no longer be trusted.
var ErrBroken = &Error{Code: "INTERNAL", Message: "the engine instance trapped and was discarded"}
