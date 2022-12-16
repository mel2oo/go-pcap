package sets

import (
	"encoding/json"
	"sort"

	"github.com/pkg/errors"
	"golang.org/x/exp/constraints"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type OrderedSet[T constraints.Ordered] map[T]struct{}

func NewOrderedSet[T constraints.Ordered](vs ...T) OrderedSet[T] {
	return OrderedSet[T](NewSet(vs...))
}

func (s OrderedSet[T]) Equals(other OrderedSet[T]) bool {
	return Set[T](s).Equals(other.AsSet())
}

func (s OrderedSet[T]) IsEmpty() bool {
	return Set[T](s).IsEmpty()
}

func (s OrderedSet[T]) Size() int {
	return Set[T](s).Size()
}

func (s OrderedSet[T]) Contains(v T) bool {
	return Set[T](s).Contains(v)
}

func (s OrderedSet[T]) ContainsAny(vs ...T) bool {
	return Set[T](s).ContainsAny(vs...)
}

func (s OrderedSet[T]) ContainsAll(vs ...T) bool {
	return Set[T](s).ContainsAll(vs...)
}

func (s OrderedSet[T]) Insert(vs ...T) {
	Set[T](s).Insert(vs...)
}

func (s OrderedSet[T]) Delete(vs ...T) {
	Set[T](s).Delete(vs...)
}

func (s OrderedSet[T]) Union(other OrderedSet[T]) {
	Set[T](s).Union(Set[T](other))
}

func (s OrderedSet[T]) Intersect(other OrderedSet[T]) {
	Set[T](s).Intersect(Set[T](other))
}

// Marshals as a sorted slice.
func (s OrderedSet[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.AsSlice())
}

func (s *OrderedSet[T]) UnmarshalJSON(text []byte) error {
	var slice []T
	if err := json.Unmarshal(text, &slice); err != nil {
		return errors.Wrapf(err, "failed to unmarshal stringset")
	}
	*s = make(OrderedSet[T], len(slice))
	for _, elt := range slice {
		(*s)[elt] = struct{}{}
	}
	return nil
}

func (s OrderedSet[T]) Clone() OrderedSet[T] {
	return maps.Clone(s)
}

// Returns the set as a sorted slice.
func (s OrderedSet[T]) AsSlice() []T {
	rv := make([]T, 0, len(s))
	for x := range s {
		rv = append(rv, x)
	}
	slices.Sort(rv)
	return rv
}

// Returns the set as a Set. Changes to the returned Set will be reflected in
// this set.
func (s OrderedSet[T]) AsSet() Set[T] {
	return Set[T](s)
}

// Creates a new set from the intersection of sets.
func IntersectOrdered[T constraints.Ordered](sets ...OrderedSet[T]) OrderedSet[T] {
	if len(sets) == 0 {
		return OrderedSet[T]{}
	}

	// Sort by set length.  Starting with the smallest set reduces
	// the work we need to do.
	sort.Slice(sets, func(i, j int) bool {
		return len(sets[i]) < len(sets[j])
	})

	base := sets[0].Clone()
	for _, next := range sets[1:] {
		base.Intersect(next)
	}

	return base
}

// Applies the given function to each element of an ordered set. Returns the
// resulting set of function outputs.
func MapOrdered[T, U constraints.Ordered](ts OrderedSet[T], f func(T) U) OrderedSet[U] {
	return AsOrderedSet(Map(ts.AsSet(), f))
}
