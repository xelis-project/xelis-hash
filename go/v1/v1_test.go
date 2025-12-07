package v1

import (
	"slices"
	"testing"
)

func TestZeroInput(t *testing.T) {
	var input [BytesArrayInput]byte
	scratchPad := NewScratchPad()

	hash, err := XelisHash(&input, scratchPad)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	expected := []byte{
		0x0e, 0xbb, 0xbd, 0x8a, 0x31, 0xed, 0xad, 0xfe, 0x09, 0x8f, 0x2d, 0x77, 0x0d, 0x84,
		0xb7, 0x19, 0x58, 0x86, 0x75, 0xab, 0x88, 0xa0, 0xa1, 0x70, 0x67, 0xd0, 0x0a, 0x8f,
		0x36, 0x18, 0x22, 0x65}

	if !slices.Equal(expected, hash[:]) {
		t.Errorf("Hash mismatch:\nGot:      %x\nExpected: %x", hash, expected)
	}
	t.Logf("Hash: %x", hash)
}

func TestXelisInput(t *testing.T) {
	var input [BytesArrayInput]byte
	custom := []byte("xelis-hashing-algorithm")
	copy(input[:], custom)

	scratchPad := NewScratchPad()
	hash, err := XelisHash(&input, scratchPad)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	expected := []byte{
		106, 106, 173, 8, 207, 59, 118, 108, 176, 196, 9, 124, 250, 195, 3,
		61, 30, 146, 238, 182, 88, 83, 115, 81, 139, 56, 3, 28, 176, 86, 68, 21,
	}

	if !slices.Equal(expected, hash[:]) {
		t.Errorf("Hash mismatch:\nGot:      %x\nExpected: %x", hash, expected)
	}

	t.Logf("Hash: %x", hash)
}

func TestScratchPadReuse(t *testing.T) {
	var input [BytesArrayInput]byte
	scratchPad := NewScratchPad()

	hash1, err := XelisHash(&input, scratchPad)
	if err != nil {
		t.Fatalf("First hash failed: %v", err)
	}

	hash2, err := XelisHash(&input, scratchPad)
	if err != nil {
		t.Fatalf("Second hash failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Hash mismatch:\nGot:      %x\nExpected: %x", hash1, hash2)
	}
}

func BenchmarkXelisHashV1(b *testing.B) {
	var input [BytesArrayInput]byte
	copy(input[:], []byte("benchmark data"))
	scratchPad := NewScratchPad()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = XelisHash(&input, scratchPad)
	}
}
