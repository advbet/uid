uid
===

[![GoDoc](https://godoc.org/github.com/advbet/uid?status.svg)](https://godoc.org/github.com/advbet/uid)

This is a Go library for UUID generation. In addition to RFC4122 V5 UUID type,
this library can generate two custom UUID types:

- Time+Rand based. UUID from high precision 64bit time value and
  cryptographically secure 64bit random sequence.
- Two ints based. UUID from a 64 bit and a 62 bit unsigned integer (two bits of
  the second half hold the variant type).
