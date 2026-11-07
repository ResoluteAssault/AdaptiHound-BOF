#pragma once
static inline void ah_string(ah_buffer &b, const char *s) { ah_json_bytes(&b, s ? s : "", ah_len(s)); }
static inline void ah_int64(ah_buffer &b, int64_t n) {
    uint64_t magnitude = n < 0 ? static_cast<uint64_t>(-(n + 1)) + 1 : static_cast<uint64_t>(n);
    if (n < 0) AH_TEXT(&b, "-");
    char digits[32]; const char *s = ah_decimal(digits + sizeof(digits), magnitude);
    ah_append(&b, s, ah_len(s));
}
class ah_fields final {
    ah_buffer &b;
    size_t start;
    bool first = true;
public:
    explicit ah_fields(ah_buffer &buffer) : b(buffer), start(buffer.length) {}
    bool contains(const char *name) const {
        unsigned int depth = 0;
        for (size_t i = start; i < b.length; ++i) {
            char c = b.data[i];
            if (c == '[' || c == '{') ++depth;
            else if ((c == ']' || c == '}') && depth) --depth;
            else if (c == '"') {
                size_t begin = ++i;
                while (i < b.length && b.data[i] != '"') { if (b.data[i] == '\\' && i + 1 < b.length) ++i; ++i; }
                if (!depth && i + 1 < b.length && b.data[i + 1] == ':' && i - begin == ah_len(name)) {
                    bool equal = true;
                    for (size_t n = 0; equal && n < i - begin; ++n) equal = ah_lower(b.data[begin + n]) == ah_lower(name[n]);
                    if (equal) return true;
                }
            }
        }
        return false;
    }
    void key(const char *name) { if (!first) { AH_TEXT(&b, ","); } first = false; ah_string(b, name); AH_TEXT(&b, ":"); }
    void text(const char *name, const char *value) { key(name); ah_string(b, value); }
    void nullable_text(const char *name, const char *value) { key(name); if (value) ah_string(b, value); else AH_TEXT(&b, "null"); }
    void boolean(const char *name, bool value) { key(name); if (value) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false"); }
    void number(const char *name, int64_t value) { key(name); ah_int64(b, value); }
};
static inline bool ah_prefix(const char *s, const char *prefix) { while (*prefix) if (ah_lower(*s++) != ah_lower(*prefix++)) return false; return true; }
static const char *ah_parent(const char *dn) {
    bool escaped = false;
    for (; *dn; ++dn) {
        if (escaped) escaped = false;
        else if (*dn == '\\') escaped = true;
        else if (*dn == ',') return dn + 1;
    }
    return "";
}
static inline bool ah_has(const ah_object *o, const char *name, const char *value) {
    for (ah_value *v = o->values(name); v; v = v->next) if (ah_eq(v->data, value)) return true;
    return false;
}
static inline char *ah_upper(ah_arena &arena, const char *source) {
    wchar_t *wide = ah_wide(source);
    if (!wide) { arena.failed = true; return nullptr; }
    int n = KERNEL32$LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, wide, -1, nullptr, 0);
    wchar_t *upper = n > 0 ? ah_alloc<wchar_t>(static_cast<size_t>(n) * sizeof(wchar_t)) : nullptr;
    char *out = nullptr;
    if (upper && KERNEL32$LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, wide, -1, upper, n)) out = arena.utf8(upper);
    else arena.failed = true;
    ah_free(wide); ah_free(upper);
    return out;
}
static inline void ah_text_array(ah_buffer &b, ah_value *values) {
    AH_TEXT(&b, "["); bool first = true;
    for (ah_value *v = values; v; v = v->next) { if (!first) { AH_TEXT(&b, ","); } first = false; ah_string(b, v->data); }
    AH_TEXT(&b, "]");
}
