package sets

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicSetOperations(t *testing.T) {
	s := NewSet[int]()
	assert.Equal(t, len(s), 0)
	assert.Equal(t, map[int]struct{}(s), map[int]struct{}{})

	s.Insert(1)
	assert.Equal(t, s, NewSet(1))

	s.Intersect(NewSet(1, 2))
	assert.Equal(t, s, NewSet(1))

	s.Union(NewSet(1, 2))
	assert.Equal(t, s, NewSet(1, 2))

	s.Delete(1)
	assert.Equal(t, s, NewSet(2))
}

func TestSetJson(t *testing.T) {
	s := NewSet(3, 2, 1)

	bs, err := json.Marshal(s)
	assert.NoError(t, err)

	var deserialized Set[int]
	err = json.Unmarshal(bs, &deserialized)
	assert.NoError(t, err)

	assert.Equal(t, deserialized, s, "s == unmarshal(marshal(s))")
}

func TestSetIntersect(t *testing.T) {
	testCases := []struct {
		name     string
		sets     []Set[int]
		expected Set[int]
	}{
		{
			name:     "empty",
			sets:     nil,
			expected: NewSet[int](),
		},
		{
			name:     "overlap",
			sets:     []Set[int]{NewSet(1, 2), NewSet(2, 3)},
			expected: NewSet(2),
		},
		{
			name:     "no overlap",
			sets:     []Set[int]{NewSet(1, 2), NewSet(3, 4)},
			expected: NewSet[int](),
		},
	}

	for _, tc := range testCases {
		intersected := Intersect(tc.sets...)
		assert.Equal(t, tc.expected, intersected, tc.name)
	}
}
