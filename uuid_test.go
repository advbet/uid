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

func TestUUIDScanBytes(t *testing.T) {
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

func TestUUIDScanBytesErrors(t *testing.T) {
	var err error
	var uuid UUID

	// Invalid data length
	err = uuid.Scan([]byte{1, 2, 3})
	assert.Error(t, err)

	// Invalid type
	err = uuid.Scan(15)
	assert.Error(t, err)
}

func TestUUIDScanString(t *testing.T) {
	var err error
	var uuid UUID

	expected, err := FromString("16c8034b-5a29-73bc-49e4-80ab6cf505e4")
	assert.NoError(t, err)

	src := "16c8034b-5a29-73bc-49e4-80ab6cf505e4"

	err = uuid.Scan(src)
	assert.NoError(t, err)
	assert.Equal(t, expected, uuid)
}

func TestUUIDScanStringErrors(t *testing.T) {
	var err error
	var uuid UUID

	// Invalid uuid format
	err = uuid.Scan("16c8034b-5a29-73bc-49e4-80ab6cf505kk")
	assert.Error(t, err)

	// Invalid uuid string
	err = uuid.Scan("")
	assert.Error(t, err)
}

func TestNewInts(t *testing.T) {
	// Setting max allowed values should result UUID with all 1 bits except
	// for variant type
	uuid := NewInts(0xffffffffffffffff, 0x3fffffffffffffff)
	expected := UUID{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	assert.Equal(t, expected, uuid)

	// Setting min uint64 values should return zero value UUID
	uuid = NewInts(0, 0)
	assert.True(t, uuid == Zero)
}

func TestNewIntsRange(t *testing.T) {
	tests := map[string]struct {
		a      uint64
		b      uint64
		panics bool
	}{
		"zero values":       {a: 0, b: 0},
		"max a":             {a: 0xffffffffffffffff, b: 1},
		"max b":             {a: 1, b: 0x3fffffffffffffff},
		"b one over max":    {a: 1, b: 0x4000000000000000, panics: true},
		"b highest bit set": {a: 1, b: 0x8000000000000000, panics: true},
		"b all bits set":    {a: 1, b: 0xffffffffffffffff, panics: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.panics {
				assert.Panics(t, func() { NewInts(tc.a, tc.b) })
				return
			}
			uuid := NewInts(tc.a, tc.b)

			// Accepted values must round trip without losing bits
			a, b, err := uuid.ParseIntBased()
			require.NoError(t, err)
			assert.Equal(t, tc.a, a)
			assert.Equal(t, tc.b, b)
		})
	}
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
	expected := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	tests := map[string]struct {
		val string
	}{
		"canonical":       {val: "00010203-0405-0607-0809-0a0b0c0d0e0f"},
		"upper case":      {val: "00010203-0405-0607-0809-0A0B0C0D0E0F"},
		"without hyphens": {val: "000102030405060708090a0b0c0d0e0f"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var actual UUID

			err := actual.UnmarshalText([]byte(tc.val))
			assert.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestUUIDUnmarshalTextError(t *testing.T) {
	tests := map[string]struct {
		val string
	}{
		"empty":                            {val: ""},
		"too short":                        {val: "15"},
		"one symbol too short":             {val: "00010203-0405-0607-0809-0a0b0c0d0e0"},
		"one symbol too long":              {val: "00010203-0405-0607-0809-0a0b0c0d0e0f0"},
		"invalid symbols":                  {val: "00010203-0405-0607-0809-0a0b0c0d0exx"},
		"invalid symbols without hyphens":  {val: "000102030405060708090a0b0c0d0exx"},
		"misplaced hyphen":                 {val: "0001020-30405-0607-0809-0a0b0c0d0e0f"},
		"hex symbol instead of 1st hyphen": {val: "00010203a0405-0607-0809-0a0b0c0d0e0f"},
		"hex symbol instead of 2nd hyphen": {val: "00010203-0405a0607-0809-0a0b0c0d0e0f"},
		"hex symbol instead of 3rd hyphen": {val: "00010203-0405-0607a0809-0a0b0c0d0e0f"},
		"hex symbol instead of 4th hyphen": {val: "00010203-0405-0607-0809a0a0b0c0d0e0f"},
		"hyphens at the end":               {val: "000102030405060708090a0b0c0d0e0f----"},
		"extra hyphens":                    {val: "-00010203-0405-0607-0809-0a0b0c0d0e0f-"},
		"hyphen instead of hex symbol":     {val: "00010203-0405-0607-0809-0a0b0c0d"},
		"only hyphens":                     {val: "------------------------------------"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Receiver must be left untouched when parsing fails
			expected := UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
			uuid := expected

			err := uuid.UnmarshalText([]byte(tc.val))
			assert.Error(t, err)
			assert.Equal(t, expected, uuid)
		})
	}
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
