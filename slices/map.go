package slices

// Apply f to each element of slice in order, returning the results.
func Map[T1, T2 any](slice []T1, f func(T1) T2) []T2 {
	result, _ := MapWithErr[T1, T2](slice, func(t T1) (T2, error) {
		return f(t), nil
	})
	return result
}

// Apply f to each element of slice in order, returning the results.  Returns
// an error if f returns a non-nil error on any element.
func MapWithErr[T1, T2 any](slice []T1, f func(T1) (T2, error)) (rv []T2, err error) {
	if slice == nil {
		return nil, nil
	}

	rv = make([]T2, len(slice))
	for i, v := range slice {
		rv[i], err = f(v)
		if err != nil {
			return nil, err
		}
	}

	return rv, nil
}
