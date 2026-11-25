uid
===

[![GoDoc](https://godoc.org/github.com/advbet/uid?status.svg)](https://godoc.org/github.com/advbet/uid)

This is a Go library for UUID generation. In addition to RFC4122 V5 UUID type,
this library can generate two custom UUID types:

- Time+Rand based. UUID from high precision 64bit time value and
  cryptographically secure 62bit random sequence. It exposes its creation time,
  so it must not be used as a secret or an access token.
- Two 64 bit ints based. UUID from two concatenated int64 values.
