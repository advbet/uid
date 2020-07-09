package uid

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUUIDIsZero(t *testing.T) {
	var uuid UUID

	assert.True(t, uuid == Zero)

	uuid = UUID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	assert.False(t, uuid == Zero)
}

func TestUUIDValue(t *testing.T) {
	uuid := UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	expected := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	val, err := uuid.Value()
	assert.NoError(t, err)
	assert.Equal(t, expected, val)

	// Mutations in source value should produce mutations in internal DB
	// values
	uuid[0]++
	assert.Equal(t, expected, val)
}

func TestUUIDScan(t *testing.T) {
	var err error
	var uuid UUID

	expected := UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	err = uuid.Scan(src)
	assert.NoError(t, err)
	assert.Equal(t, expected, uuid)

	// Mutations in internal DB value should not produce mutations in
	// scanned value
	src[0]++
	assert.Equal(t, expected, uuid)
}

func TestUUIDScanErrors(t *testing.T) {
	var err error
	var uuid UUID

	// Invalid data length
	err = uuid.Scan([]byte{1, 2, 3})
	assert.Error(t, err)

	// Invalid type
	err = uuid.Scan(15)
	assert.Error(t, err)
}

func TestNewInts(t *testing.T) {
	// Setting max uint64 values should result UUID with all 1 bits except
	// for variant type
	uuid := NewInts(0xffffffffffffffff, 0xffffffffffffffff)
	expected := UUID{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	assert.Equal(t, expected, uuid)

	// Setting min uint64 values should return zero value UUID
	uuid = NewInts(0, 0)
	assert.True(t, uuid == Zero)
}

func TestUUIDParseIntBased(t *testing.T) {
	a := uint64(rand.Int63())
	b := uint64(rand.Int63()) & 0x1fffffffffffffff

	uuid := NewInts(a, b)
	aa, bb, err := uuid.ParseIntBased()
	assert.NoError(t, err)
	assert.Equal(t, a, aa, "extracted a part does not match")
	assert.Equal(t, b, bb, "extracted b part does not match")

	// Time based UUID should not be parsable to integers without errors
	_, _, err = NewTimeRand().ParseIntBased()
	assert.Error(t, err)
}

func TestNewTimeSequence(t *testing.T) {
	now := time.Now()
	uuid1 := NewTime(now)
	uuid2 := NewTime(now.Add(time.Second))

	// Later UUID should always be bigger than previous UUIDs
	// Assert uuid1 < uuid2
	assert.True(t, bytes.Compare(uuid1[0:], uuid2[0:]) == -1)
}

func TestNewTimeVariant(t *testing.T) {
	uuid := NewTime(time.Now())
	variant := uuid[8] >> 6

	// Time and rand based UUIDs should have variant value 01xx xxxx
	assert.Equal(t, byte(0x03), variant)
}

func TestNewTimeRandSequence(t *testing.T) {
	uuid1 := NewTimeRand()
	time.Sleep(time.Millisecond)
	uuid2 := NewTimeRand()

	// Later UUID should always be bigger than previous UUIDs
	// Assert uuid1 < uuid2
	assert.True(t, bytes.Compare(uuid1[0:], uuid2[0:]) == -1)
}

func TestNewTimeRandVariant(t *testing.T) {
	uuid := NewTimeRand()
	variant := uuid[8] >> 6

	// Time and rand based UUIDs should have variant value 01xx xxxx
	assert.Equal(t, byte(0x01), variant)
}

func TestUUIDString(t *testing.T) {
	uuid := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	expected := "00010203-0405-0607-0809-0a0b0c0d0e0f"

	assert.Equal(t, expected, uuid.String())
}

func TestUUIDMarshalText(t *testing.T) {
	uuid := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	expected := `00010203-0405-0607-0809-0a0b0c0d0e0f`

	actual, err := uuid.MarshalText()
	assert.NoError(t, err)
	assert.Equal(t, []byte(expected), actual)
}

func TestUUIDUnmarshalText(t *testing.T) {
	val := `00010203-0405-0607-0809-0a0b0c0d0e0f`
	expected := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var actual UUID

	err := actual.UnmarshalText([]byte(val))
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestUUIDUnmarshalTextError(t *testing.T) {
	var err error
	var uuid UUID

	err = uuid.UnmarshalText([]byte(`15`))
	assert.Error(t, err)

	err = uuid.UnmarshalText([]byte(`invalid`))
	assert.Error(t, err)

	// Valid length, but invalid symbols "xx"
	err = uuid.UnmarshalText([]byte(`0102030405060708090a0b0c0d0exx`))
	assert.Error(t, err)
}

func TestUUIDMarshalXML(t *testing.T) {
	uuid := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	expected := `<marshal><uuid>00010203-0405-0607-0809-0a0b0c0d0e0f</uuid></marshal>`
	type marshal struct {
		UUID UUID `xml:"uuid"`
	}
	v := marshal{UUID: uuid}

	actual, err := xml.Marshal(v)
	assert.NoError(t, err)
	assert.Equal(t, []byte(expected), actual)
}

func TestUUIDMarshalXMLAttr(t *testing.T) {
	uuid := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	expected := `<marshal UUID="00010203-0405-0607-0809-0a0b0c0d0e0f"></marshal>`
	type marshal struct {
		UUID UUID `xml:",attr"`
	}
	v := marshal{UUID: uuid}

	actual, err := xml.Marshal(v)
	assert.NoError(t, err)
	assert.Equal(t, []byte(expected), actual)
}

func TestUUIDUnmarshalXML(t *testing.T) {
	expected := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var actual struct {
		UUID UUID `xml:"UUID"`
	}

	xmlBlob := []byte(`<root><UUID>00010203-0405-0607-0809-0A0B0C0D0E0F</UUID></root>`)
	err := xml.Unmarshal(xmlBlob, &actual)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual.UUID)
}

func TestUUIDUnmarshalXMLAttr(t *testing.T) {
	expected := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var actual struct {
		UUID UUID `xml:",attr"`
	}

	xmlBlob := []byte(`<root UUID="00010203-0405-0607-0809-0A0B0C0D0E0F"></root>`)
	err := xml.Unmarshal(xmlBlob, &actual)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual.UUID)
}

func TestUUIDMarshalJSON(t *testing.T) {
	uuid := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	expected := `{"uuid":"00010203-0405-0607-0809-0a0b0c0d0e0f"}`
	var v = struct {
		UUID UUID `json:"uuid"`
	}{
		UUID: uuid,
	}

	actual, err := json.Marshal(v)
	assert.NoError(t, err)
	assert.Equal(t, []byte(expected), actual)
}

func TestUUIDUnmarshalJSON(t *testing.T) {
	val := `{"uuid": "00010203-0405-0607-0809-0a0b0c0d0e0f"}`
	expected := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var actual struct {
		UUID UUID `json:"uuid"`
	}

	err := json.Unmarshal([]byte(val), &actual)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual.UUID)
}

func TestNewV5(t *testing.T) {
	hostname := "example.net"

	ns, err := FromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8") // https://tools.ietf.org/html/rfc4122#appendix-C
	require.NoError(t, err)

	expected, err := FromString("90d38b76-e7dd-5733-8575-0d06a98e8b70")
	require.NoError(t, err)

	actual := NewV5(ns, hostname)
	assert.Equal(t, expected, actual)
}
