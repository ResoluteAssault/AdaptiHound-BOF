#pragma once

static inline uint32_t ah_u32(const unsigned char *p) { return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24; }
static inline uint16_t ah_u16(const unsigned char *p) { return static_cast<uint16_t>(p[0] | p[1] << 8); }
static inline bool ah_sid_string(char out[192], const unsigned char *p, size_t n) {
    if (n < 8 || p[0] != 1 || p[1] > 15 || static_cast<size_t>(8 + p[1] * 4) > n) return false;
    size_t used = 0; out[used++] = 'S'; out[used++] = '-'; out[used++] = '1';
    uint64_t authority = 0;
    for (unsigned int i = 2; i < 8; ++i) authority = (authority << 8) | p[i];
    for (unsigned int i = 0; i <= p[1]; ++i) {
        char digits[32]; const char *s = ah_decimal(digits + sizeof(digits), i ? ah_u32(p + 8 + (i - 1) * 4) : authority);
        out[used++] = '-'; while (*s) out[used++] = *s++;
    }
    out[used] = 0;
    return true;
}
static inline char *ah_sid(ah_arena &arena, const unsigned char *p, size_t n) {
    char out[192]; return ah_sid_string(out, p, n) ? arena.copy(out) : nullptr;
}
static inline bool ah_guid_string(char out[37], const unsigned char *p, size_t n) {
    if (n != 16) return false;
    static const unsigned char order[] = {3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
    static const char hex[] = "0123456789abcdef";
    size_t used = 0;
    for (unsigned int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[used++] = '-';
        unsigned char value = p[order[i]]; out[used++] = hex[value >> 4]; out[used++] = hex[value & 15];
    }
    out[used] = 0;
    return true;
}
static inline char *ah_guid(ah_arena &arena, const unsigned char *p, size_t n) {
    char out[37];if(!ah_guid_string(out,p,n))return nullptr;
    for(char *c=out;*c;++c)if(*c>='a'&&*c<='f')*c-=32;
    return arena.copy(out);
}
