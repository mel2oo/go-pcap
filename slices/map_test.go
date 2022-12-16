package slices

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestMap(t *testing.T) {
	type testStruct struct {
		F1 string
	}

	unused := func(s testStruct) string {
		return ""
	}
	getF1 := func(s testStruct) string {
		return s.F1
	}

	testCases := []struct {
		name     string
		slice    []testStruct
		f        func(testStruct) string
		expected []string
	}{
		{
			name:     "empty map",
			slice:    nil,
			f:        unused,
			expected: nil,
		},
		{
			name:     "field projection",
			slice:    []testStruct{{F1: "1"}, {F1: "2"}},
			f:        getF1,
			expected: []string{"1", "2"},
		},
	}

	for _, tc := range testCases {
		actual := Map(tc.slice, tc.f)
		assert.Equal(t, tc.expected, actual, tc.name)
	}
}

func TestMapWithErr(t *testing.T) {
	type testStruct struct {
		F1 string
	}

	unused := func(s testStruct) (string, error) {
		return "", nil
	}
	getF1 := func(s testStruct) (string, error) {
		return s.F1, nil
	}
	getErr := func(s testStruct) (string, error) {
		return "", errors.New("test error path")
	}

	testCases := []struct {
		name        string
		slice       []testStruct
		f           func(testStruct) (string, error)
		expected    []string
		expectedErr bool
	}{
		{
			name:     "empty map",
			slice:    nil,
			f:        unused,
			expected: nil,
		},
		{
			name:     "field projection",
			slice:    []testStruct{{F1: "1"}, {F1: "2"}},
			f:        getF1,
			expected: []string{"1", "2"},
		},
		{
			name:        "error",
			slice:       []testStruct{{F1: "1"}, {F1: "2"}},
			f:           getErr,
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		actual, err := MapWithErr(tc.slice, tc.f)
		if tc.expectedErr {
			assert.Error(t, err, tc.name)
		} else {
			assert.Equal(t, tc.expected, actual, tc.name)
		}
	}
}
