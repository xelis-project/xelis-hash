package v2

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
		126, 219, 112, 240, 116, 133, 115, 144, 39, 40, 164,
		105, 30, 158, 45, 126, 64, 67, 238, 52, 200, 35,
		161, 19, 144, 211, 214, 225, 95, 190, 146, 27,
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
		199, 114, 154, 28, 4, 164, 196, 178, 117, 17, 148,
		203, 125, 228, 51, 145, 162, 222, 106, 202, 205,
		55, 244, 178, 94, 29, 248, 242, 98, 221, 158, 179,
	}

	if !slices.Equal(expected, hash[:]) {
		t.Errorf("Hash mismatch:\nGot:      %x\nExpected: %x", hash, expected)
	}
}

func BenchmarkXelisHashV2(b *testing.B) {
	input := make([]byte, 112)
	scratchPad := NewScratchPad()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = XelisHash(input, scratchPad)
	}
}
