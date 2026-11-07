#pragma once

static uint32_t ah_sha1_rol(uint32_t value, unsigned int bits) { return (value << bits) | (value >> (32 - bits)); }

static void ah_sha1(const unsigned char *data, size_t length, unsigned char output[20]) {
    uint32_t h[5] = {0x67452301U, 0xefcdab89U, 0x98badcfeU, 0x10325476U, 0xc3d2e1f0U};
    uint64_t bit_length = static_cast<uint64_t>(length) * 8;
    size_t padded = length + 1;
    while (padded % 64 != 56) ++padded;
    for (size_t offset = 0; offset < padded + 8; offset += 64) {
        uint32_t w[80] = {};
        for (unsigned int i = 0; i < 64; ++i) {
            size_t position = offset + i;
            unsigned char value = 0;
            if (position < length) value = data[position];
            else if (position == length) value = 0x80;
            else if (position >= padded) value = static_cast<unsigned char>(bit_length >> ((7 - (position - padded)) * 8));
            w[i / 4] |= static_cast<uint32_t>(value) << ((3 - (i % 4)) * 8);
        }
        for (unsigned int i = 16; i < 80; ++i) w[i] = ah_sha1_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (unsigned int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999U; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1U; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcU; }
            else { f = b ^ c ^ d; k = 0xca62c1d6U; }
            uint32_t next = ah_sha1_rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = ah_sha1_rol(b, 30); b = a; a = next;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    for (unsigned int i = 0; i < 20; ++i) {
        output[i] = h[i / 4] >> ((3 - (i % 4)) * 8);
    }
}

static char *ah_thumbprint(ah_arena &arena, const ah_value *certificate) {
    if (!certificate) return arena.copy("");
    unsigned char digest[20]; ah_sha1(reinterpret_cast<const unsigned char *>(certificate->data), certificate->size, digest);
    static const char hex[] = "0123456789ABCDEF";
    char *out = static_cast<char *>(arena.alloc(41));
    if (!out) return nullptr;
    for (unsigned int i = 0; i < 20; ++i) { out[i * 2] = hex[digest[i] >> 4]; out[i * 2 + 1] = hex[digest[i] & 15]; }
    out[40] = 0;
    return out;
}
