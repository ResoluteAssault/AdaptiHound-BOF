#pragma once

class ah_directory final : public ah_directory_state {
public:
    ah_arena arena;
    ah_object *objects = nullptr, *tail = nullptr;
    size_t count = 0;
    explicit ah_directory(size_t maximum, size_t initial_chunk = 65536) : arena(maximum, initial_chunk) {}
    ah_object *add(const wchar_t *type, const char *dn) {
        ah_object *o = arena.make<ah_object>();
        if (!o) return nullptr;
        o->type = type; o->dn = arena.copy(dn);
        if (tail) tail->next = o; else objects = o;
        tail = o; ++count;
        return o;
    }
    ah_attr *attribute(ah_object *o, const char *name) {
        ah_attr *a = o->attr(name);
        if (a) return a;
        a = arena.make<ah_attr>();
        if (!a) return nullptr;
        a->name = arena.copy(name); a->next = o->attributes; o->attributes = a;
        return a;
    }
    bool value(ah_attr *a, const char *data, size_t n) {
        if (!a) return false;
        ah_value *v = arena.make<ah_value>();
        if (!v) return false;
        v->data = arena.copy(data, n); v->size = n;
        if (a->tail) a->tail->next = v; else a->values = v;
        a->tail = v;
        return v->data != nullptr;
    }
};

class ah_index final {
    struct slot { const char *key; ah_object *value; };
    slot *slots = nullptr; size_t capacity = 0;
    ah_arena *owner = nullptr;

    char *normalized(const char *key) const {
        bool unicode = false;
        for (const unsigned char *p = reinterpret_cast<const unsigned char *>(key); *p; ++p) if (*p >= 128) unicode = true;
        if (!unicode) return nullptr;
        wchar_t *wide = ah_wide(key);
        int n = wide ? KERNEL32$LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, wide, -1, nullptr, 0) : 0;
        wchar_t *upper = n > 0 ? ah_alloc<wchar_t>(static_cast<size_t>(n) * sizeof(wchar_t)) : nullptr;
        char *out = nullptr;
        if (upper && KERNEL32$LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, wide, -1, upper, n)) {
            n = KERNEL32$WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, upper, -1, nullptr, 0, nullptr, nullptr);
            out = n > 0 ? ah_alloc(static_cast<size_t>(n)) : nullptr;
            if (out && !KERNEL32$WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, upper, -1, out, n, nullptr, nullptr)) { ah_free(out); out = nullptr; }
        }
        if (!out) owner->failed = true;
        ah_free(wide); ah_free(upper);
        return out;
    }
    static uint64_t hash(const char *s) { uint64_t h = 1469598103934665603ULL; while (*s) { h ^= static_cast<unsigned char>(ah_lower(*s++)); h *= 1099511628211ULL; } return h; }
public:
    ah_index read_only_view(ah_arena &reader) const {ah_index view=*this;view.owner=&reader;return view;}
    bool init(ah_arena &arena, size_t count) {
        owner = &arena;
        slots = nullptr; capacity = 0;
        if (count > SIZE_MAX / 4) { arena.failed = true; return false; }
        const size_t wanted = count * 4;
        capacity = 16;
        while (capacity < wanted) {
            if (capacity > SIZE_MAX / 2) { arena.failed = true; capacity = 0; return false; }
            capacity *= 2;
        }
        if (capacity > SIZE_MAX / sizeof(slot)) { arena.failed = true; capacity = 0; return false; }
        slots = static_cast<slot *>(arena.alloc(capacity * sizeof(slot)));
        return slots != nullptr;
    }
    void put(const char *key, ah_object *value) {
        if (!slots || !key || !*key) return;
        char *folded = normalized(key);
        if (owner->failed) { ah_free(folded); return; }
        const char *canonical = folded ? folded : key;
        size_t i = hash(canonical) & (capacity - 1);
        const size_t initial = i;
        while (slots[i].key && !ah_eq(slots[i].key, canonical)) {
            i = (i + 1) & (capacity - 1);
            if (i == initial) { owner->failed = true; ah_free(folded); return; }
        }
        const char *stored = folded ? owner->copy(folded) : key;
        if (stored) slots[i] = {stored, value};
        ah_free(folded);
    }
    ah_object *find(const char *key) const {
        if (!slots || !key || !*key) return nullptr;
        char *folded = normalized(key);
        if (owner->failed) { ah_free(folded); return nullptr; }
        const char *canonical = folded ? folded : key;
        size_t i = hash(canonical) & (capacity - 1);
        ah_object *out = nullptr;
        const size_t initial = i;
        while (slots[i].key) { if (ah_eq(slots[i].key, canonical)) { out = slots[i].value; break; } i = (i + 1) & (capacity - 1); if (i == initial) break; }
        ah_free(folded);
        return out;
    }
};

static inline int64_t ah_integer(const ah_object *o, const char *name) { return ah_integer(o->values(name)); }
