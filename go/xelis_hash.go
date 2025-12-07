package xelis_hash

import (
	"encoding/hex"
	"errors"
)

const HashSize = 32

var ErrInvalidHashLength = errors.New("invalid hash length")

type Hash [HashSize]byte

func (h *Hash) Bytes() []byte {
	return h[:]
}

func (h *Hash) String() string {
	return hex.EncodeToString(h[:])
}

func FromBytes(data []byte) (Hash, error) {
	var h Hash
	if len(data) != HashSize {
		return h, ErrInvalidHashLength
	}
	copy(h[:], data)
	return h, nil
}

func FromString(s string) (Hash, error) {
	var h Hash
	data, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	return FromBytes(data)
}
