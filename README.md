# XELIS Hash

XELIS Hash is expected to run on CPU and GPUs with a controlled gap.
It is relying on two famous algorithms: ChaCha8 and Blake3.

## V3

Same base as the V2 but with a scratchpad of 544 KB.

Stage 1 and (Final) stage 4 are the same as V2.

Stage 3 has been modified to increase memory accesses while having a random memory access pattern.

## V2

New version use a scratchpad of ~440 KB which can be reused at each hash.

Stage 1 will randomize the scratchpad based on the input used as a key for the ChaCha8 stream cipher.
The key is a Blake3 hash of (previous hash + input chunk).
 
First nonce is based on the first 12 bytes of the input's blake3 hash result.
The input is splitted into several 32 bytes chunks padded with zeroes if size is smaller.
It cannot be parallelized due to the nonce based on the previous iteration.

Stage 2 has been removed because the whole work is now done in stage 3.

Stage 3 is expected to do a lot of random access in memory while being forced to stay sequential.
There is 4 reads and 2 writes per iteration, making it memory bound.
A branching part is included in the inner loop to be power-hungry and reduce efficiency of FPGA and GPUs.

(Final) stage 4 is using Blake3 algorithm to hash the whole scratchpad to give a final good-quality hash.
It is also used to prevent skipping a part of the scratchpad, to force it to be fully computed.

Blake3 and ChaCha8 are used as they are really fast and can be highly parallelized, one thread can have high hashrate to reduce verification time.

Expected time per hash is around 1.20-1.50ms.

## Features

- `v1`: deprecated algorithm
- `v2`: new algorithm with 440 KB scratchpad
- `v3`: new algorithm version based on the v2 with bigger scratchpad and others changes
- `tracker`: track branches selection, memory accesses and generate charts for it.