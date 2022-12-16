package gid

import (
	"database/sql/driver"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
)

const (
	alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	baseBigInt = big.NewInt(62)
)

type ID interface {
	GetType() string
	GetUUID() uuid.UUID
	String() string
}

// Base ID structure. Embed this in your own IDs.
// This will implement part of the GID interface for you.
type baseID uuid.UUID

func (bid baseID) GetUUID() uuid.UUID {
	return uuid.UUID(bid)
}

func (i *baseID) Scan(src interface{}) error {
	var aUUID uuid.UUID
	err := aUUID.Scan(src)
	if err != nil {
		return errors.Wrap(err, "could not scan gid")
	}

	*i = baseID(aUUID)

	return nil
}

func (i baseID) Value() (driver.Value, error) {
	return i.GetUUID().Value()
}

// To support JSON marshaling/unmarshaling, individual gid types must implement
// encoding.TextMarshaler and encoding.TextUnmarshaler.
// In order to allow the individual gid types to have valid zero values, baseID
// does not know about the tag. Thus, it cannot implement those interfaces.
func (i baseID) MarshalText() ([]byte, error) {
	return nil, errors.Errorf("text marshaling unimplemented, please override MarshalText on the specific gid type.")
}

func (i *baseID) UnmarshalText(data []byte) error {
	return errors.Errorf("JSON unmarshaling unimplemented, please override UnmarshalText on the specific gid type.")
}

func toText(gid ID) ([]byte, error) {
	return []byte(String(gid)), nil
}

func fromText(dst interface{}, txt []byte) error {
	return ParseIDAs(string(txt), dst)
}

func String(gid ID) string {
	return fmt.Sprintf("%s_%s", gid.GetType(), encodeUUID(gid.GetUUID()))
}

func assignTo(assigner ID, dstID interface{}) error {
	v := reflect.ValueOf(assigner)
	dst := reflect.ValueOf(dstID)

	if reflect.PtrTo(v.Type()) != dst.Type() {
		return errors.Errorf("mismatched assignment types, can not assign %v to %v", v.Type(), dst.Type())
	}
	dst.Elem().Set(v)
	return nil
}

func encodeUUID(u uuid.UUID) string {
	uuidBs := [16]byte(u)
	n := big.NewInt(0)
	n.SetBytes(uuidBs[:])

	destBs := make([]byte, 0, 22)
	for n.Cmp(big.NewInt(0)) > 0 {
		r := big.NewInt(0)
		r.Mod(n, baseBigInt)
		n = n.Div(n, baseBigInt)
		destBs = append([]byte{alphabet[r.Int64()]}, destBs...)
	}

	// Always return a 22-character encoding, which is the maximum length
	// of an encoded UUID.  Pad the front with 0s if necessary.
	return fmt.Sprintf("%022s", string(destBs))
}

func decodeUUID(s string) (uuid.UUID, error) {
	var bigI big.Int
	for _, c := range []byte(s) {
		i := strings.IndexByte(alphabet, c)
		if i < 0 {
			return uuid.Nil, fmt.Errorf("unexpected character %c in base62 literal", c)
		}
		bigI.Mul(&bigI, baseBigInt)
		bigI.Add(&bigI, big.NewInt(int64(i)))
	}

	uuidBytes := bigI.Bytes()
	if len(uuidBytes) > 16 {
		return uuid.Nil, errors.Errorf("cannot have more than 16 bytes of UUID")
	} else if len(uuidBytes) < 16 {
		// Make sure we always pass 16 bytes to uuid.FromBytes, or else it will fail.
		tmp := make([]byte, 16)
		// The zero padding need to go to the front / most significant position.
		startOffset := 16 - len(uuidBytes)
		copy(tmp[startOffset:], uuidBytes)
		uuidBytes = tmp
	}

	id, err := uuid.FromBytes(uuidBytes)
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}
