package v3

import (
	"encoding/binary"
	"math"
	"unsafe"

	"github.com/chocolatkey/chacha8"
	"github.com/xelis-project/xelis-hash/aes"
	"github.com/xelis-project/xelis-hash/hash"
	"lukechampine.com/blake3"
	"lukechampine.com/uint128"
)

const (
	MemorySize      = 531 * 128
	ScratchpadIters = 2
	BufferSize      = MemorySize / 2
	MemorySizeBytes = MemorySize * 8
)

var Key = [16]byte{'x', 'e', 'l', 'i', 's', 'h', 'a', 's', 'h', '-', 'p', 'o', 'w', '-', 'v', '3'}

type ScratchPad [MemorySize]uint64

func murmurhash3(seed uint64) uint64 {
	seed ^= seed >> 55
	seed *= 0xff51afd7ed558ccd
	seed ^= seed >> 32
	seed *= 0xc4ceb9fe1a85ec53
	seed ^= seed >> 15
	return seed
}

func mapIndex(x uint64) int {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	// multiply-high reduction: get high 64 bits of x * BufferSize
	// (x * BufferSize) >> 64
	t1 := uint128.From64(x)
	t2 := uint128.From64(uint64(BufferSize))
	prod := t1.MulWrap(t2)
	return int(prod.Hi)
}

func pickHalf(seed uint64) bool {
	return (murmurhash3(seed) & (1 << 58)) != 0
}

func isqrt(n uint64) uint64 {
	if n < 2 {
		return n
	}

	// Compute floating-point square root as an approximation
	approx := uint64(math.Sqrt(float64(n)))

	// Verify and adjust if necessary
	if approx*approx > n {
		return approx - 1
	} else if (approx+1)*(approx+1) <= n {
		return approx + 1
	}
	return approx
}

func modularPower(base, exp, mod uint64) uint64 {
	result := uint64(1)
	base %= mod

	for exp > 0 {
		if exp&1 == 1 {
			result = mulmod(result, base, mod)
		}
		base = mulmod(base, base, mod)
		exp /= 2
	}

	return result
}

// mulmod computes (a * b) % m avoiding overflow
func mulmod(a, b, m uint64) uint64 {
	t1 := uint128.From64(a)
	t2 := uint128.From64(b)
	prod := t1.MulWrap(t2)
	mod := uint128.From64(m)
	return prod.Mod(mod).Lo
}

// Stage3 performs the complex memory operations with branching
func Stage3(scratchPad *ScratchPad) error {
	key := Key
	var block [16]byte

	// Split scratchpad
	memBufferA := scratchPad[:BufferSize]
	memBufferB := scratchPad[BufferSize:]

	addrA := memBufferB[BufferSize-1]
	addrB := memBufferA[BufferSize-1] >> 32

	r := 0

	for i := 0; i < ScratchpadIters; i++ {
		indexA := mapIndex(addrA)
		memA := memBufferA[indexA]

		indexB := mapIndex(memA ^ addrB)
		memB := memBufferB[indexB]

		binary.LittleEndian.PutUint64(block[0:8], memB)
		binary.LittleEndian.PutUint64(block[8:16], memA)

		aes.CipherRound(&block, &key)

		hash1 := binary.LittleEndian.Uint64(block[0:8])
		hash2 := binary.LittleEndian.Uint64(block[8:16])

		result := ^(hash1 ^ hash2)

		for j := 0; j < BufferSize; j++ {
			indexA := mapIndex(result)
			a := memBufferA[indexA]

			indexB := mapIndex(a ^ (^bits_RotateRight64(result, uint(r))))
			b := memBufferB[indexB]

			var c uint64
			if r < BufferSize {
				c = memBufferA[r]
			} else {
				c = memBufferB[r-BufferSize]
			}

			if r < MemorySize-1 {
				r++
			} else {
				r = 0
			}

			branchIdx := uint8(bits_RotateLeft64(result, uint(c)) & 0xf)

			var v uint64
			switch branchIdx {
			case 0:
				// combine_u64((a + i), isqrt(b + j)) % (murmurhash3(c ^ result ^ i ^ j) | 1)
				t1 := uint128.New(isqrt(b+uint64(j)), a+uint64(i)) // New(lo, hi)
				denom := uint128.From64(murmurhash3(c^result^uint64(i)^uint64(j)) | 1)
				v = t1.Mod(denom).Lo
			case 1:
				// ROTL((c + i) % isqrt(b | 2), i + j) * isqrt(a + j)
				sqrt := isqrt(b | 2)
				if sqrt == 0 {
					sqrt = 1
				}
				t1 := (c + uint64(i)) % sqrt
				t2 := bits_RotateLeft64(t1, uint(i+j))
				t3 := isqrt(a + uint64(j))
				v = t2 * t3
			case 2:
				// (isqrt(a + i) * isqrt(c + j)) ^ (b + i + j)
				t1 := isqrt(a + uint64(i))
				t2 := isqrt(c + uint64(j))
				t3 := t1 * t2
				v = t3 ^ (b + uint64(i) + uint64(j))
			case 3:
				v = (a + b) * c
			case 4:
				v = (b - c) * a
			case 5:
				v = c - a + b
			case 6:
				v = a - b + c
			case 7:
				v = b*c + a
			case 8:
				v = c*a + b
			case 9:
				v = a * b * c
			case 10:
				t1 := uint128.New(b, a) // New(lo, hi)
				t2 := uint128.From64(c | 1)
				v = t1.Mod(t2).Lo
			case 11:
				t1 := uint128.New(c, b)                                    // New(lo, hi)
				t2 := uint128.New(a|2, bits_RotateLeft64(result, uint(r))) // New(lo, hi)
				if t2.Cmp(t1) > 0 {
					v = c
				} else {
					v = t1.Mod(t2).Lo
				}
			case 12:
				t1 := uint128.New(a, c) // New(lo, hi)
				t2 := uint128.From64(b | 4)
				v = t1.Div(t2).Lo
			case 13:
				t1 := uint128.New(b, bits_RotateLeft64(result, uint(r))) // New(lo, hi)
				t2 := uint128.New(c|8, a)                                // New(lo, hi)
				if t1.Cmp(t2) > 0 {
					v = t1.Div(t2).Lo
				} else {
					v = a ^ b
				}
			case 14:
				// (combine_u64(b, a) * c) >> 64
				t1 := uint128.New(a, b) // New(lo, hi)
				prod := t1.MulWrap64(c)
				v = prod.Hi
			case 15:
				// (combine_u64(a, c) * combine_u64(result.rotate_right(r), b)) >> 64
				rr := bits_RotateRight64(result, uint(r))
				t1 := uint128.New(c, a)  // New(lo, hi)
				t2 := uint128.New(b, rr) // New(lo, hi)
				prod := t1.MulWrap(t2)
				v = prod.Hi
			}

			seed := v ^ result
			result = bits_RotateLeft64(seed, uint(r))

			useBufferB := pickHalf(v)
			indexT := mapIndex(seed)
			var t uint64
			if useBufferB {
				t = memBufferB[indexT] ^ result
			} else {
				t = memBufferA[indexT] ^ result
			}

			indexA2 := mapIndex(t ^ result ^ 0x9e3779b97f4a7c15)
			indexB2 := mapIndex(uint64(indexA2) ^ ^result ^ 0xd2b74407b1ce6e93)

			oldA := memBufferA[indexA2]
			memBufferA[indexA2] = t
			memBufferB[indexB2] ^= oldA ^ bits_RotateRight64(t, uint(i+j))
		}

		addrA = modularPower(addrA, addrB, result)
		addrB = isqrt(result) * uint64(r+1) * isqrt(addrA)
	}

	return nil
}

// Stage1 generates the scratchpad using ChaCha8 (same as v2 but with v3's memory size)
func Stage1(input []byte, scratchPad *ScratchPad) error {
	// Convert scratchpad to bytes
	scratchPadBytes := (*[MemorySizeBytes]byte)(unsafe.Pointer(scratchPad))[:]

	// Reset scratchpad
	for i := range scratchPadBytes {
		scratchPadBytes[i] = 0
	}

	const ChunkSize = 32
	const NonceSize = 12

	outputOffset := 0
	nonce := make([]byte, NonceSize)

	// Generate nonce from input
	inputHash := blake3.Sum256(input)
	copy(nonce, inputHash[:NonceSize])

	numChunks := (len(input) + ChunkSize - 1) / ChunkSize

	for chunkIndex := 0; chunkIndex*ChunkSize < len(input); chunkIndex++ {
		start := chunkIndex * ChunkSize
		end := start + ChunkSize
		if end > len(input) {
			end = len(input)
		}
		chunk := input[start:end]

		// Concatenate input hash with chunk
		tmp := make([]byte, hash.HashSize*2)
		copy(tmp[0:hash.HashSize], inputHash[:])
		copy(tmp[hash.HashSize:hash.HashSize+len(chunk)], chunk)

		// Hash it
		inputHash = blake3.Sum256(tmp)

		cipher, err := chacha8.New(inputHash[:], nonce)
		if err != nil {
			return err
		}

		// Calculate output size for this iteration
		remainingOutputSize := MemorySizeBytes - outputOffset
		chunksLeft := numChunks - chunkIndex
		chunkOutputSize := remainingOutputSize / chunksLeft
		currentOutputSize := remainingOutputSize
		if currentOutputSize > chunkOutputSize {
			currentOutputSize = chunkOutputSize
		}

		// Apply keystream
		offset := chunkIndex * currentOutputSize
		part := scratchPadBytes[offset : offset+currentOutputSize]
		cipher.XORKeyStream(part, part)

		outputOffset += currentOutputSize

		// Update nonce
		nonceStart := currentOutputSize - NonceSize
		if nonceStart < 0 {
			nonceStart = 0
		}
		copy(nonce, part[nonceStart:])
	}

	return nil
}

func XelisHash(input []byte, scratchPad *ScratchPad) (hash.Hash, error) {
	// Use v3's Stage1 with correct memory size
	err := Stage1(input, scratchPad)
	if err != nil {
		return hash.Zero(), err
	}

	// V3's custom Stage3
	err = Stage3(scratchPad)
	if err != nil {
		return hash.Zero(), err
	}

	// Stage4: hash the whole scratchpad
	scratchPadBytes := (*[MemorySizeBytes]byte)(unsafe.Pointer(scratchPad))[:]
	return blake3.Sum256(scratchPadBytes), nil
}

func NewScratchPad() *ScratchPad {
	return &ScratchPad{}
}

// Helper functions
func bits_RotateLeft64(x uint64, k uint) uint64 {
	const n = 64
	s := k & (n - 1)
	return x<<s | x>>(n-s)
}

func bits_RotateRight64(x uint64, k uint) uint64 {
	const n = 64
	s := k & (n - 1)
	return x>>s | x<<(n-s)
}
