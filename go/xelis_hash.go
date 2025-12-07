package xelis_hash

import (
	"errors"

	hash "github.com/xelis-project/xelis-hash/hash"
	v1 "github.com/xelis-project/xelis-hash/v1"
)

func HashV1(input []byte) (hash.Hash, error) {
	var padded [v1.BytesArrayInput]byte
	if len(input) <= v1.BytesArrayInput {
		copy(padded[:], input)
	} else {
		return hash.Zero(), errors.New("input too long for v1 hash (max 120 bytes)")
	}

	scratchPad := v1.NewScratchPad()
	return v1.XelisHash(&padded, scratchPad)
}
