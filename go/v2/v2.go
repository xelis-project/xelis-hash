package v2

import (
	"encoding/binary"
	"unsafe"

	"github.com/chocolatkey/chacha8"
	"github.com/xelis-project/xelis-hash/aes"
	"lukechampine.com/blake3"
	"lukechampine.com/uint128"
)

const (
	MemorySize      = 429 * 128
	ScratchpadIters = 3
	BufferSize      = MemorySize / 2
	ChunkSize       = 32
	NonceSize       = 12
	MemorySizeBytes = MemorySize * 8
	HashSize        = 32
)

var Key = [16]byte{'x', 'e', 'l', 'i', 's', 'h', 'a', 's', 'h', '-', 'p', 'o', 'w', '-', 'v', '2'}

type ScratchPad [MemorySize]uint64

// Stage1 generates the scratchpad using ChaCha8
func Stage1(input []byte, scratchPad *ScratchPad) error {
	// Convert scratchpad to bytes
	scratchPadBytes := (*[MemorySizeBytes]byte)(unsafe.Pointer(scratchPad))[:]

	// Reset scratchpad
	for i := range scratchPadBytes {
		scratchPadBytes[i] = 0
	}

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
		tmp := make([]byte, HashSize*2)
		copy(tmp[0:HashSize], inputHash[:])
		copy(tmp[HashSize:HashSize+len(chunk)], chunk)

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

func isqrt(n uint64) uint64 {
	if n < 2 {
		return n
	}

	x := n
	y := (x + 1) >> 1

	for y < x {
		x = y
		y = (x + n/x) >> 1
	}

	return x
}

// Stage3 performs random memory accesses and branching
func Stage3(scratchPad *ScratchPad) error {
	var block [16]byte

	// Split scratchpad into two buffers
	memBufferA := scratchPad[:BufferSize]
	memBufferB := scratchPad[BufferSize:]

	addrA := memBufferB[BufferSize-1]
	addrB := memBufferA[BufferSize-1] >> 32

	r := 0

	for i := 0; i < ScratchpadIters; i++ {
		indexA := int(addrA % uint64(BufferSize))
		indexB := int(addrB % uint64(BufferSize))

		memA := memBufferA[indexA]
		memB := memBufferB[indexB]

		binary.LittleEndian.PutUint64(block[0:8], memB)
		binary.LittleEndian.PutUint64(block[8:16], memA)

		aes.CipherRound(&block, &Key)

		hash1 := binary.LittleEndian.Uint64(block[0:8])
		hash2 := memA ^ memB
		result := ^(hash1 ^ hash2)

		for j := 0; j < BufferSize; j++ {
			indexA := int(result % uint64(BufferSize))
			indexB := int((^bits_RotateRight64(result, uint(r))) % uint64(BufferSize))

			a := memBufferA[indexA]
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

			branchIdx := uint8((bits_RotateLeft64(result, uint(c)) & 0xf))

			var v uint64
			switch branchIdx {
			case 0:
				v = result ^ (bits_RotateLeft64(c, uint(i*j)) ^ b)
			case 1:
				v = result ^ (bits_RotateRight64(c, uint(i*j)) ^ a)
			case 2:
				v = result ^ (a ^ b ^ c)
			case 3:
				v = result ^ ((a + b) * c)
			case 4:
				v = result ^ ((b - c) * a)
			case 5:
				v = result ^ (c - a + b)
			case 6:
				v = result ^ (a - b + c)
			case 7:
				v = result ^ (b*c + a)
			case 8:
				v = result ^ (c*a + b)
			case 9:
				v = result ^ (a * b * c)
			case 10:
				// combine_u64(a, b) % (c | 1)
				// Rust: combine_u64(high, low) where a is high, b is low
				t1 := uint128.New(b, a) // New(lo, hi)
				t2 := uint128.From64(c | 1)
				v = result ^ t1.Mod(t2).Lo
			case 11:
				// combine_u64(b, c) % combine_u64(result.rotate_left(r), a | 2)
				// Rust: combine_u64(high, low)
				t1 := uint128.New(c, b)                                    // New(lo, hi) where b is high, c is low
				t2 := uint128.New(a|2, bits_RotateLeft64(result, uint(r))) // New(lo, hi)
				v = result ^ t1.Mod(t2).Lo
			case 12:
				// combine_u64(c, a) / (b | 4)
				// Rust: combine_u64(high, low) where c is high, a is low
				t1 := uint128.New(a, c) // New(lo, hi)
				t2 := uint128.From64(b | 4)
				v = result ^ t1.Div(t2).Lo
			case 13:
				// combine_u64(result.rotate_left(r), b) where first arg is high
				// combine_u64(a, c|8) where a is high
				t1 := uint128.New(b, bits_RotateLeft64(result, uint(r))) // New(lo, hi)
				t2 := uint128.New(c|8, a)                                // New(lo, hi)
				if t1.Cmp(t2) > 0 {
					v = result ^ t1.Div(t2).Lo
				} else {
					v = result ^ (a ^ b)
				}
			case 14:
				// (combine_u64(b, a) * c) >> 64
				// Rust wrapping_mul on u128 then >> 64 gets high 64 bits
				t1 := uint128.New(a, b) // New(lo, hi) where b is high, a is low
				prod := t1.MulWrap64(c) // Wrapping mul
				v = result ^ prod.Hi
			case 15:
				// (combine_u64(a, c) * combine_u64(result.rotate_right(r), b)) >> 64
				// Rust wrapping_mul on u128 then >> 64 gets high 64 bits
				rr := bits_RotateRight64(result, uint(r))
				t1 := uint128.New(c, a)  // New(lo, hi) where a is high, c is low
				t2 := uint128.New(b, rr) // New(lo, hi) where rr is high, b is low
				prod := t1.MulWrap(t2)   // Wrapping mul
				v = result ^ prod.Hi
			}

			result = bits_RotateLeft64(v, 1)

			t := memBufferA[BufferSize-j-1] ^ result
			memBufferA[BufferSize-j-1] = t
			memBufferB[j] ^= bits_RotateRight64(t, uint(result))
		}

		addrA = result
		addrB = isqrt(result)
	}

	return nil
}

// Stage4 hashes the entire scratchpad with Blake3
func Stage4(scratchPad *ScratchPad) [HashSize]byte {
	scratchPadBytes := (*[MemorySizeBytes]byte)(unsafe.Pointer(scratchPad))[:]
	return blake3.Sum256(scratchPadBytes)
}

func XelisHash(input []byte, scratchPad *ScratchPad) ([HashSize]byte, error) {
	err := Stage1(input, scratchPad)
	if err != nil {
		return [HashSize]byte{}, err
	}

	err = Stage3(scratchPad)
	if err != nil {
		return [HashSize]byte{}, err
	}

	return Stage4(scratchPad), nil
}

func NewScratchPad() *ScratchPad {
	return &ScratchPad{}
}

// Helper functions for bit rotation
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
