//go:build amd64 && !purego

package aes

import (
	"golang.org/x/sys/cpu"
)

// hasAESNI indicates whether AES-NI instructions are available
var hasAESNI = cpu.X86.HasAES

// CipherRound performs a single AES round using AES-NI instructions if available
func CipherRound(block *[16]byte, key *[16]byte) {
	if hasAESNI {
		aesCipherRoundAsm(block, key)
	} else {
		CipherRoundGeneric(block, key)
	}
}

// aesCipherRoundAsm is implemented in assembly using AES-NI
func aesCipherRoundAsm(block *[16]byte, key *[16]byte)
