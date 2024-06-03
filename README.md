# XELIS Hash

XELIS Hash is expected to run on CPU and GPUs with a controlled gap.
It is relying on two famous algorithms: ChaCha20 and Blake3.

## Summary

Scratchpad of almost 1 MB is created (it can be reused at each hash).

Stage 1 will randomize the scratchpad based on the input used as a key for the ChaCha20 stream cipher.
The input is splitted in 32 bytes chunks, it cannot be parallelized due to the nonce based on the previous iteration.

Stage 3 is expected to do a lot of random access in memory while being forced to stay sequential.
A branching part is included in the inner loop to be power-hungry and reduce efficiency of FPGA and GPUs.

Final stage is using Blake3 algorithm to hash the whole scratchpad to give a final good-quality hash.