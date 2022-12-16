package sets

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicOperations(t *testing.T) {
	s := NewOrderedSet[int]()
	assert.Equal(t, len(s), 0)
	assert.Equal(t, map[int]struct{}(s), map[int]struct{}{})

	s.Insert(1)
	assert.Equal(t, s, NewOrderedSet(1))

	s.Intersect(NewOrderedSet(1, 2))
	assert.Equal(t, s, NewOrderedSet(1))

	s.Union(NewOrderedSet(1, 2))
	assert.Equal(t, s, NewOrderedSet(1, 2))

	s.Delete(1)
	assert.Equal(t, s, NewOrderedSet(2))
}

func TestOrderedSetJson(t *testing.T) {
	s := NewOrderedSet(3, 2, 1)

	bs, err := json.Marshal(s)
	assert.NoError(t, err)

	var deserialized OrderedSet[int]
	err = json.Unmarshal(bs, &deserialized)
	assert.NoError(t, err)

	assert.Equal(t, deserialized, s, "s == unmarshal(marshal(s))")
}

func TestJsonOrdering(t *testing.T) {
	bs1, err := json.Marshal(NewOrderedSet(1, 2, 3))
	assert.NoError(t, err)

	bs2, err := json.Marshal(NewOrderedSet(3, 2, 1))
	assert.NoError(t, err)

	assert.Equal(t, string(bs1), string(bs2), "marshal(s) == marshal(s)")
}

func TestOrderedSetIntersect(t *testing.T) {
	testCases := []struct {
		name     string
		sets     []OrderedSet[int]
		expected OrderedSet[int]
	}{
		{
			name:     "empty",
			sets:     nil,
			expected: NewOrderedSet[int](),
		},
		{
			name:     "overlap",
			sets:     []OrderedSet[int]{NewOrderedSet(1, 2), NewOrderedSet(2, 3)},
			expected: NewOrderedSet(2),
		},
		{
			name:     "no overlap",
			sets:     []OrderedSet[int]{NewOrderedSet(1, 2), NewOrderedSet(3, 4)},
			expected: NewOrderedSet[int](),
		},
	}

	for _, tc := range testCases {
		intersected := IntersectOrdered(tc.sets...)
		assert.Equal(t, tc.expected, intersected, tc.name)
	}
}
