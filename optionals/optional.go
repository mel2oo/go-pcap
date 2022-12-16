package optionals

import "encoding/json"

// An Optional[T] is an option type.
//
// The JSON serialization/deserialization of an Optional[T] is compatible with
// that of a *T.
type Optional[T any] struct {
	value *T
}

func Some[T any](t T) Optional[T] {
	return Optional[T]{
		value: &t,
	}
}

func None[T any]() Optional[T] {
	return Optional[T]{}
}

func (opt Optional[T]) IsSome() bool {
	return opt.value != nil
}

func (opt Optional[T]) IsNone() bool {
	return opt.value == nil
}

func (opt Optional[T]) Get() (T, bool) {
	var defaultResult T
	if opt.IsNone() {
		return defaultResult, false
	}

	return *opt.value, true
}

// Returns the value inhabiting this option. If this is None, then returns the
// given default value.
func (opt Optional[T]) GetOrDefault(defaultValue T) T {
	if opt.IsNone() {
		return defaultValue
	}
	return *opt.value
}

// Returns the value inhabiting this option. If this is None, then returns the
// result of calling the supplied function.
func (opt Optional[T]) GetOrCompute(computeValue func() (T, error)) (T, error) {
	if opt.IsNone() {
		return computeValue()
	}
	return *opt.value, nil
}

// A version of GetOrCompute that is guaranteed to not error.
func (opt Optional[T]) GetOrComputeNoError(computeValue func() T) T {
	if opt.IsNone() {
		return computeValue()
	}
	return *opt.value
}

func Bind[T, U any](opt Optional[T], f func(T) Optional[U]) Optional[U] {
	if opt.IsNone() {
		return None[U]()
	}

	return f(*opt.value)
}

func Map[T, U any](opt Optional[T], f func(T) U) Optional[U] {
	if opt.IsNone() {
		return None[U]()
	}

	return Some(f(*opt.value))
}

func (opt Optional[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(opt.value)
}

func (opt *Optional[T]) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &opt.value)
}
