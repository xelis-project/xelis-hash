//go:build !amd64 || purego

package aes

// CipherRound performs a single AES round using software implementation
func CipherRound(block *[16]byte, key *[16]byte) {
	CipherRoundGeneric(block, key)
}
