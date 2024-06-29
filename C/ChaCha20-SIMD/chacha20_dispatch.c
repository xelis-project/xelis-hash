#include "cpu_features.h"
#include "chacha20.h"

static bool initialized = false;
static cpu_features_t f;

void chacha_init()
{
    get_cpu_features(&f);

    initialized = true;
}

void chacha_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *in, uint8_t *out, size_t bytes, uint32_t rounds)
{

    if (!initialized)
    {
        chacha_init();
    }

    if (f.HW_AVX2)
    {
        chacha_encrypt_avx2(key, nonce, in, out, bytes, rounds);
        return;
    }

    if (f.HW_SSE2)
    {
        chacha_encrypt_sse2(key, nonce, in, out, bytes, rounds);
        return;
    }

    chacha_encrypt_portable(key, nonce, in, out, bytes, rounds);
}