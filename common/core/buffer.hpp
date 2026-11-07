#pragma once
extern "C" void __cxa_pure_virtual() {}
#include "memory.hpp"

class ah_buffer final {
public:
    char *data = nullptr;
    size_t length = 0, capacity = 0, limit, initial_capacity;
    bool failed = false;
    explicit ah_buffer(size_t max_size, size_t initial_size = 65536) noexcept : limit(max_size ? max_size : SIZE_MAX), initial_capacity(initial_size ? initial_size : 1) {}
    ~ah_buffer() { ah_memory_release(data); }
    ah_buffer(const ah_buffer &) = delete;
    ah_buffer &operator=(const ah_buffer &) = delete;
};

static size_t ah_wlen(const wchar_t *s) { size_t n = 0; while (s && s[n]) ++n; return n; }
template <typename T = char>
static T *ah_alloc(size_t bytes) { return static_cast<T *>(ah_memory_allocate(bytes)); }
static void ah_free(void *p) { ah_memory_release(p); }

extern "C" void _ZdlPvy(void *p) { ah_free(p); }

static wchar_t *ah_wide(const char *s) {
    int n = KERNEL32$MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    wchar_t *out = n > 0 ? ah_alloc<wchar_t>((size_t)n * sizeof(wchar_t)) : NULL;
    if (out && !KERNEL32$MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, out, n)) { ah_free(out); out = NULL; }
    return out;
}

static void ah_append(ah_buffer *b, const char *s, size_t n) {
    if (b->failed) return;
    if (b->length > b->limit || n > b->limit - b->length) { b->failed = 1; return; }
    size_t need = b->length + n;
    if (need > b->capacity) {
        size_t cap = b->capacity ? b->capacity : (b->limit < b->initial_capacity ? b->limit : b->initial_capacity);
        while (cap < need && cap < b->limit) cap = cap > b->limit / 2 ? b->limit : cap * 2;
        char *next = b->data ? static_cast<char *>(ah_memory_reallocate(b->data, cap)) : ah_alloc(cap);
        if (!next) { b->failed = 1; return; }
        b->data = next; b->capacity = cap;
    }
    for (size_t i = 0; i < n; ++i) b->data[b->length + i] = s[i];
    b->length = need;
}
#define AH_TEXT(b, s) ah_append((b), (s), sizeof(s) - 1)

static void ah_json_bytes(ah_buffer *b, const char *s, size_t n) {
    static const char hex[] = "0123456789abcdef";
    AH_TEXT(b, "\"");
    for (size_t i = 0; i < n; ++i) {
        unsigned char ch = (unsigned char)s[i];
        if (ch == '"' || ch == '\\') { AH_TEXT(b, "\\"); ah_append(b, s + i, 1); }
        else if (ch < 32) { char esc[6] = {'\\', 'u', '0', '0', hex[ch >> 4], hex[ch & 15]}; ah_append(b, esc, 6); }
        else if (ch < 128) ah_append(b, s + i, 1);
        else {
            size_t count = ch >= 0xc2 && ch <= 0xdf ? 2 : ch >= 0xe0 && ch <= 0xef ? 3 : ch >= 0xf0 && ch <= 0xf4 ? 4 : 0;
            bool valid = count && count <= n - i;
            for (size_t j = 1; valid && j < count; ++j) valid = (static_cast<unsigned char>(s[i + j]) & 0xc0) == 0x80;
            if (valid) {
                unsigned char second = static_cast<unsigned char>(s[i + 1]);
                valid = !(ch == 0xe0 && second < 0xa0) && !(ch == 0xed && second >= 0xa0) && !(ch == 0xf0 && second < 0x90) && !(ch == 0xf4 && second >= 0x90);
            }
            if (valid) { ah_append(b, s + i, count); i += count - 1; }
            else AH_TEXT(b, "\\ufffd");
        }
    }
    AH_TEXT(b, "\"");
}
