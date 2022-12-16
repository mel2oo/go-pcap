package slices

// Returns a new slice with elements from s in reverse order.
func Reverse[T any](s []T) []T {
	// Avoid creating an empty list if s is nil.
	if s == nil {
		return nil
	}

	rev := make([]T, 0, len(s))

	// Traverse s in reverse, adding to rev.
	for i := len(s) - 1; i >= 0; i-- {
		rev = append(rev, s[i])
	}

	return rev
}
