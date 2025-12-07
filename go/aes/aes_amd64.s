#include "textflag.h"

// func aesCipherRoundAsm(block *[16]byte, key *[16]byte)
TEXT ·aesCipherRoundAsm(SB), NOSPLIT, $0-16
	MOVQ block+0(FP), AX
	MOVQ key+8(FP), BX
	
	// Load block into XMM0
	MOVOU (AX), X0
	
	// Load key into XMM1
	MOVOU (BX), X1
	
	// Perform AES round: AESENC = SubBytes + ShiftRows + MixColumns + AddRoundKey
	AESENC X1, X0
	
	// Store result back to block
	MOVOU X0, (AX)
	RET
