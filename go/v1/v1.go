package v1

import (
	"encoding/binary"
	"math/bits"
	"unsafe"

	"github.com/xelis-project/xelis-hash/go/aes"
	"github.com/xelis-project/xelis-hash/go/hash"
)

const (
	MemorySize      = 32768
	ScratchpadIters = 5000
	Iters           = 1
	BufferSize      = 42
	SlotLength      = 256
	KeccakWords     = 25
	BytesArrayInput = KeccakWords * 8
	Stage1Max       = MemorySize / KeccakWords
)

type ScratchPad [MemorySize]uint64

func Stage1(input *[KeccakWords]uint64, scratchPad *[MemorySize]uint64, aRange, bRange [2]int) {
	for i := aRange[0]; i <= aRange[1]; i++ {
		KeccakF1600(input)

		var randInt uint64 = 0
		for j := bRange[0]; j <= bRange[1]; j++ {
			pairIdx := (j + 1) % KeccakWords
			pairIdx2 := (j + 2) % KeccakWords

			targetIdx := i*KeccakWords + j
			a := input[j] ^ randInt

			// Branching
			left := input[pairIdx]
			right := input[pairIdx2]
			xor := left ^ right
			var v uint64
			switch xor & 0x3 {
			case 0:
				v = left & right
			case 1:
				v = ^(left & right)
			case 2:
				v = ^xor
			case 3:
				v = xor
			}

			b := a ^ v
			randInt = b
			scratchPad[targetIdx] = b
		}
	}
}

func XelisHash(input *[BytesArrayInput]byte, scratchPad *ScratchPad) (hash.Hash, error) {
	// Convert input bytes to u64 array
	var intInput [KeccakWords]uint64
	for i := 0; i < KeccakWords; i++ {
		intInput[i] = binary.LittleEndian.Uint64(input[i*8:])
	}

	// Stage 1
	Stage1(&intInput, (*[MemorySize]uint64)(scratchPad), [2]int{0, Stage1Max - 1}, [2]int{0, KeccakWords - 1})
	Stage1(&intInput, (*[MemorySize]uint64)(scratchPad), [2]int{Stage1Max, Stage1Max}, [2]int{0, 17})

	// Stage 2
	var slots [SlotLength]uint32
	// Convert scratchpad to u32 using unsafe pointer (no copy)
	smallPad := (*[MemorySize * 2]uint32)(unsafe.Pointer(&scratchPad[0]))

	copy(slots[:], smallPad[len(smallPad)-SlotLength:])

	var indices [SlotLength]uint16
	for iter := 0; iter < Iters; iter++ {
		for j := 0; j < len(smallPad)/SlotLength; j++ {
			// Initialize indices and precompute the total sum
			var totalSum uint32 = 0
			for k := 0; k < SlotLength; k++ {
				indices[k] = uint16(k)
				if slots[k]>>31 == 0 {
					totalSum += smallPad[j*SlotLength+k]
				} else {
					totalSum -= smallPad[j*SlotLength+k]
				}
			}

			for slotIdx := SlotLength - 1; slotIdx >= 0; slotIdx-- {
				indexInIndices := int(smallPad[j*SlotLength+slotIdx] % uint32(slotIdx+1))
				index := int(indices[indexInIndices])
				indices[indexInIndices] = indices[slotIdx]

				localSum := totalSum
				s1 := int32(slots[index] >> 31)
				padValue := smallPad[j*SlotLength+index]
				if s1 == 0 {
					localSum -= padValue
				} else {
					localSum += padValue
				}

				// Apply the sum to the slot
				slots[index] += localSum

				// Update the total sum
				s2 := int32(slots[index] >> 31)
				totalSum -= 2 * smallPad[j*SlotLength+index] * uint32(-s1+s2)
			}
		}
	}

	copy(smallPad[MemorySize*2-SlotLength:], slots[:])
	// No need to convert back - smallPad points directly to scratchPad memory

	// Stage 3
	var key [16]byte // zero key
	var block [16]byte

	addrA := (scratchPad[MemorySize-1] >> 15) & 0x7FFF
	addrB := scratchPad[MemorySize-1] & 0x7FFF

	var memBufferA [BufferSize]uint64
	var memBufferB [BufferSize]uint64

	for i := uint64(0); i < BufferSize; i++ {
		memBufferA[i] = scratchPad[(addrA+i)%MemorySize]
		memBufferB[i] = scratchPad[(addrB+i)%MemorySize]
	}

	var finalResult hash.Hash

	for i := 0; i < ScratchpadIters; i++ {
		memA := memBufferA[i%BufferSize]
		memB := memBufferB[i%BufferSize]

		binary.LittleEndian.PutUint64(block[0:8], memB)
		binary.LittleEndian.PutUint64(block[8:16], memA)

		// Use single AES round instead of full encryption
		aes.CipherRound(&block, &key)

		hash1 := binary.LittleEndian.Uint64(block[0:8])
		hash2 := memA ^ memB

		result := ^(hash1 ^ hash2)

		for j := 0; j < hash.HashSize; j++ {
			a := memBufferA[(j+i)%BufferSize]
			b := memBufferB[(j+i)%BufferSize]

			switch (result >> (j * 2)) & 0xf {
			case 0:
				result = bits.RotateLeft64(result, j) ^ b
			case 1:
				result = ^(bits.RotateLeft64(result, j) ^ a)
			case 2:
				result = ^(result ^ a)
			case 3:
				result ^= b
			case 4:
				result ^= (a + b)
			case 5:
				result ^= (a - b)
			case 6:
				result ^= (b - a)
			case 7:
				result ^= (a * b)
			case 8:
				result ^= (a & b)
			case 9:
				result ^= (a | b)
			case 10:
				result ^= (a ^ b)
			case 11:
				result ^= (a - result)
			case 12:
				result ^= (b - result)
			case 13:
				result ^= (a + result)
			case 14:
				result ^= (result - a)
			case 15:
				result ^= (result - b)
			}
		}

		addrB = result & 0x7FFF
		memBufferA[i%BufferSize] = result
		memBufferB[i%BufferSize] = scratchPad[addrB]

		addrA = (result >> 15) & 0x7FFF
		scratchPad[addrA] = result

		index := ScratchpadIters - i - 1
		if index < 4 {
			var resultBytes [8]byte
			binary.BigEndian.PutUint64(resultBytes[:], result)
			copy(finalResult[index*8:(ScratchpadIters-i)*8], resultBytes[:])
		}
	}

	return finalResult, nil
}

// NewScratchPad creates a new zeroed scratchpad
func NewScratchPad() *ScratchPad {
	return &ScratchPad{}
}
