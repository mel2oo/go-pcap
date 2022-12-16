package optionals

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoneJSON(t *testing.T) {
	// Test that None and nil serialize to the same thing.
	none := None[int]()
	null := (*int)(nil)
	noneJSON, err := json.Marshal(none)
	assert.NoError(t, err)
	nullJSON, err := json.Marshal(null)
	assert.NoError(t, err)
	assert.Equal(t, nullJSON, noneJSON)

	// Test that deserialize(serialize(None)) == None.
	var deserialized Optional[int]
	err = json.Unmarshal(noneJSON, &deserialized)
	assert.NoError(t, err)
	assert.Equal(t, none, deserialized)
}

func TestSomeJSON(t *testing.T) {
	// Test that Some(42) and 42 serialize to the same thing.
	v := 42
	someV := Some(v)
	pV := &v
	someVJSON, err := json.Marshal(someV)
	assert.NoError(t, err)
	pVJSON, err := json.Marshal(pV)
	assert.NoError(t, err)
	assert.Equal(t, pVJSON, someVJSON)

	// Test that deserialize(serialize(Some(42))) == Some(42).
	var deserialized Optional[int]
	err = json.Unmarshal(someVJSON, &deserialized)
	assert.NoError(t, err)
	assert.Equal(t, someV, deserialized)
}
