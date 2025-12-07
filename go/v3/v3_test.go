package v3

import (
	"slices"
	"testing"
)

func TestZeroHash(t *testing.T) {
	input := make([]byte, 112)
	scratchPad := NewScratchPad()

	hash, err := XelisHash(input, scratchPad)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	expected := [32]byte{
		105, 172, 103, 40, 94, 253, 92, 162,
		42, 252, 5, 196, 236, 238, 91, 218,
		22, 157, 228, 233, 239, 8, 250, 57,
		212, 166, 121, 132, 148, 205, 103, 163,
	}

	if !slices.Equal(expected[:], hash[:]) {
		t.Errorf("Hash mismatch:\nGot:      %x\nExpected: %x", hash, expected)
	}
}

func TestReusedScratchpad(t *testing.T) {
	input := make([]byte, 112)
	for i := range input {
		input[i] = byte(i % 256)
	}

	scratchPad := NewScratchPad()

	hash1, err := XelisHash(input, scratchPad)
	if err != nil {
		t.Fatalf("First hash failed: %v", err)
	}

	hash2, err := XelisHash(input, scratchPad)
	if err != nil {
		t.Fatalf("Second hash failed: %v", err)
	}

	for i := range hash1 {
		if hash1[i] != hash2[i] {
			t.Errorf("Hash mismatch when reusing scratchpad")
			break
		}
	}
}

func TestVerifyOutput(t *testing.T) {
	input := []byte{
		172, 236, 108, 212, 181, 31, 109, 45, 44, 242, 54, 225, 143, 133,
		89, 44, 179, 108, 39, 191, 32, 116, 229, 33, 63, 130, 33, 120, 185, 89,
		146, 141, 10, 79, 183, 107, 238, 122, 92, 222, 25, 134, 90, 107, 116,
		110, 236, 53, 255, 5, 214, 126, 24, 216, 97, 199, 148, 239, 253, 102,
		199, 184, 232, 253, 158, 145, 86, 187, 112, 81, 78, 70, 80, 110, 33,
		37, 159, 233, 198, 1, 178, 108, 210, 100, 109, 155, 106, 124, 124, 83,
		89, 50, 197, 115, 231, 32, 74, 2, 92, 47, 25, 220, 135, 249, 122,
		172, 220, 137, 143, 234, 68, 188,
	}

	scratchPad := NewScratchPad()
	hash, err := XelisHash(input, scratchPad)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	expected := []byte{
		242, 8, 176, 222, 203, 27, 104,
		187, 22, 40, 68, 73, 79, 79, 65,
		83, 138, 101, 10, 116, 194, 41, 153,
		21, 92, 163, 12, 206, 231, 156, 70, 83,
	}

	if !slices.Equal(expected, hash[:]) {
		t.Errorf("Hash mismatch:\nGot:      %x\nExpected: %x", hash, expected)
	}
}

func TestMapIndex(t *testing.T) {
	// Test that mapIndex always returns valid indices
	for i := 0; i < 10000; i++ {
		idx := mapIndex(uint64(i))
		if idx < 0 || idx >= BufferSize {
			t.Errorf("Invalid index %d from mapIndex(%d)", idx, i)
		}
	}

	// Edge cases
	if mapIndex(0) < 0 || mapIndex(0) >= BufferSize {
		t.Error("mapIndex(0) out of bounds")
	}
	if mapIndex(^uint64(0)) < 0 || mapIndex(^uint64(0)) >= BufferSize {
		t.Error("mapIndex(MAX) out of bounds")
	}
}

func TestPickHalf(t *testing.T) {
	// Test that pickHalf produces roughly 50/50 distribution
	ones := 0
	zeros := 0
	iterations := 100000

	for i := 0; i < iterations; i++ {
		if pickHalf(uint64(i)) {
			ones++
		} else {
			zeros++
		}
	}

	ratio := float64(ones) / float64(ones+zeros)
	t.Logf("pickHalf ratio: %f (ones: %d, zeros: %d)", ratio, ones, zeros)

	// Allow 5% deviation from 0.5
	if ratio < 0.45 || ratio > 0.55 {
		t.Errorf("pickHalf distribution is skewed: %f", ratio)
	}
}

func BenchmarkXelisHashV3(b *testing.B) {
	input := make([]byte, 112)
	scratchPad := NewScratchPad()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = XelisHash(input, scratchPad)
	}
}

func BenchmarkMapIndex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = mapIndex(uint64(i))
	}
}

func BenchmarkPickHalf(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = pickHalf(uint64(i))
	}
}
