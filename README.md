uid
===

[![GoDoc](https://godoc.org/bitbucket.org/advbet/uid?status.svg)](https://godoc.org/bitbucket.org/advbet/uid)

This is a Go library for UUID generation. In addition to RFC4122 V5 UUID type,
this library can generate two custom UUID types:

- Time+Rand based. UUID from high precision 64bit time value and
  cryptographically secure 64bit random sequence.
- Two 64 bit ints based. UUID from two concatenated int64 values.
