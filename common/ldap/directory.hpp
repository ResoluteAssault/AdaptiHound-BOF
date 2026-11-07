#pragma once

static inline size_t ah_len(const char *s) { size_t n = 0; while (s && s[n]) ++n; return n; }
static inline char ah_lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c; }
static inline bool ah_eq(const char *a, const char *b) {
    if (!a || !b) return a == b;
    while (*a && *b) { if (ah_lower(*a++) != ah_lower(*b++)) return false; }
    return *a == *b;
}
static inline bool ah_weq(const wchar_t *a, const wchar_t *b) {
    while (*a && *b) { if (*a++ != *b++) return false; }
    return *a == *b;
}

class ah_arena final {
    struct block { block *next; size_t used, size; };
    block *head = nullptr;
    size_t allocated = 0, limit, chunk_size;
public:
    bool failed = false;
    explicit ah_arena(size_t maximum, size_t initial_chunk = 65536) noexcept : limit(maximum ? maximum : SIZE_MAX), chunk_size(initial_chunk ? initial_chunk : 65536) {}
    ah_arena(const ah_arena &) = delete;
    ah_arena &operator=(const ah_arena &) = delete;
    ~ah_arena() { reset(); }
    void reset() noexcept {
        while (head) { block *next = head->next; ah_free(head); head = next; }
        allocated = 0; failed = false;
    }
    size_t allocated_bytes() const noexcept { return allocated; }
    void *alloc(size_t bytes) {
        if (failed || limit < sizeof(block)+8 || bytes > limit-sizeof(block) || bytes>SIZE_MAX-7) { failed=true;return nullptr; }
        bytes = (bytes + 7) & ~static_cast<size_t>(7);
        if(bytes>limit-sizeof(block)){failed=true;return nullptr;}
        if (!head || bytes > head->size - head->used) {
            size_t size = bytes > chunk_size ? bytes : chunk_size;
            size_t available=limit-allocated;
            if(available<sizeof(block)||bytes>available-sizeof(block)){failed=true;return nullptr;}
            if(size>available-sizeof(block))size=(available-sizeof(block))&~static_cast<size_t>(7);
            block *next = ah_alloc<block>(sizeof(block) + size);
            if (!next) { failed = true; return nullptr; }
            next->next = head; next->size = size; next->used = 0;
            head = next; allocated += size + sizeof(block);
        }
        char *out = reinterpret_cast<char *>(head + 1) + head->used;
        head->used += bytes;
        return out;
    }
    template <typename T> T *make() { return static_cast<T *>(alloc(sizeof(T))); }
    char *copy(const char *data, size_t n) {
        if (n == SIZE_MAX || (!data && n)) { failed = true; return nullptr; }
        char *out = static_cast<char *>(alloc(n + 1));
        if (out) { for (size_t i = 0; i < n; ++i) out[i] = data[i]; out[n] = 0; }
        return out;
    }
    char *copy(const char *data) { return copy(data, ah_len(data)); }
    char *utf8(const wchar_t *data) {
        int n = KERNEL32$WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, data, -1, nullptr, 0, nullptr, nullptr);
        char *out = n > 0 ? static_cast<char *>(alloc(static_cast<size_t>(n))) : nullptr;
        if (!out || !KERNEL32$WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, data, -1, out, n, nullptr, nullptr)) { failed = true; return nullptr; }
        return out;
    }
};

struct ah_value { char *data; size_t size; ah_value *next; };
struct ah_attr { char *name; ah_value *values, *tail; ah_attr *next; };
static inline uint64_t ah_unsigned(const char *text) {
    uint64_t value = 0;
    for (; *text >= '0' && *text <= '9'; ++text) {
        unsigned int digit = static_cast<unsigned int>(*text - '0');
        if (value > (UINT64_MAX - digit) / 10) return UINT64_MAX;
        value = value * 10 + digit;
    }
    return value;
}
static inline int64_t ah_signed(const char *text) {
    bool negative = *text == '-';
    uint64_t value = ah_unsigned(text + (negative ? 1 : 0));
    if (negative) return value >= (1ULL << 63) ? (-9223372036854775807LL - 1) : -static_cast<int64_t>(value);
    return value > static_cast<uint64_t>(9223372036854775807LL) ? 9223372036854775807LL : static_cast<int64_t>(value);
}
static inline int64_t ah_integer(const ah_value *value) {
    if (!value) return 0;
    bool numeric = value->size && (value->data[0] == '-' || (value->data[0] >= '0' && value->data[0] <= '9'));
    if (!numeric && value->size == 8) {
        uint64_t raw = 0;
        for (unsigned int i = 0; i < 8; ++i) raw |= static_cast<uint64_t>(static_cast<unsigned char>(value->data[i])) << (i * 8);
        return static_cast<int64_t>(raw);
    }
    if (!numeric && value->size == 4) {
        const unsigned char *p = reinterpret_cast<unsigned char *>(value->data);
        uint32_t raw = static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
        return static_cast<int32_t>(raw);
    }
    return ah_signed(value->data);
}
static inline char *ah_concat(ah_arena &arena, const char *a, const char *b, const char *c = "") {
    size_t x = ah_len(a), y = ah_len(b), z = ah_len(c);
    if (x > SIZE_MAX - y || x + y > SIZE_MAX - z || x + y + z == SIZE_MAX) { arena.failed = true; return nullptr; }
    char *out = static_cast<char *>(arena.alloc(x + y + z + 1));
    if (out) {
        size_t i = 0;
        for (size_t n = 0; n < x; ++n) out[i++] = a[n];
        for (size_t n = 0; n < y; ++n) out[i++] = b[n];
        for (size_t n = 0; n < z; ++n) out[i++] = c[n];
        out[i] = 0;
    }
    return out;
}
static inline char *ah_decimal(char *end, uint64_t n) {
    *--end = 0;
    do { *--end = static_cast<char>('0' + n % 10); n /= 10; } while (n);
    return end;
}
