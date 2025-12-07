package xelis_hash

import (
	"errors"

	hash "github.com/xelis-project/xelis-hash/hash"
	v1 "github.com/xelis-project/xelis-hash/v1"
	v2 "github.com/xelis-project/xelis-hash/v2"
	v3 "github.com/xelis-project/xelis-hash/v3"
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

func HashV2(input []byte) (hash.Hash, error) {
	scratchPad := v2.NewScratchPad()
	return v2.XelisHash(input, scratchPad)
}

func HashV3(input []byte) (hash.Hash, error) {
	scratchPad := v3.NewScratchPad()
	return v3.XelisHash(input, scratchPad)
}
