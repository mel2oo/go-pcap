package slices

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReverse(t *testing.T) {
	testCases := []struct {
		name     string
		slice    []int
		expected []int
	}{
		{
			name: "nil",
		},
		{
			name:     "singleton",
			slice:    []int{1},
			expected: []int{1},
		},
		{
			name:     "reverse",
			slice:    []int{2, 1},
			expected: []int{1, 2},
		},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.expected, Reverse(tc.slice), tc.name)
	}
}
