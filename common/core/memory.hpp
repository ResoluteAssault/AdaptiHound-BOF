#pragma once

static inline bool ah_size_add(size_t left, size_t right, size_t &result) noexcept {
    if (right > SIZE_MAX - left) return false;
    result = left + right;
    return true;
}
static inline bool ah_size_multiply(size_t left, size_t right, size_t &result) noexcept {
    if (left && right > SIZE_MAX / left) return false;
    result = left * right;
    return true;
}

class ah_memory_budget final {
    size_t maximum;
    alignas(8) volatile LONG64 live_bytes = 0, peak_bytes = 0, failures = 0;
    static uint64_t read(volatile LONG64 &value) noexcept {
        return static_cast<uint64_t>(InterlockedCompareExchange64(&value, 0, 0));
    }
public:
    explicit ah_memory_budget(size_t limit = 0) noexcept : maximum(limit) {}
    bool reserve(size_t bytes) noexcept {
        uint64_t before = read(live_bytes);
        const uint64_t ceiling = maximum ? maximum : SIZE_MAX;
        for (;;) {
            if (before > ceiling || bytes > ceiling - before) { note_failure(); return false; }
            const uint64_t after = before + bytes;
            const uint64_t observed = static_cast<uint64_t>(InterlockedCompareExchange64(&live_bytes, static_cast<LONG64>(after), static_cast<LONG64>(before)));
            if (observed == before) {
                uint64_t peak = read(peak_bytes);
                while (peak < after) {
                    uint64_t previous = static_cast<uint64_t>(InterlockedCompareExchange64(&peak_bytes, static_cast<LONG64>(after), static_cast<LONG64>(peak)));
                    if (previous == peak) break;
                    peak = previous;
                }
                return true;
            }
            before = observed;
        }
    }
    void release(size_t bytes) noexcept {
        uint64_t before = read(live_bytes);
        while (static_cast<uint64_t>(InterlockedCompareExchange64(&live_bytes, static_cast<LONG64>(before - bytes), static_cast<LONG64>(before))) != before) before = read(live_bytes);
    }
    void note_failure() noexcept { InterlockedIncrement64(&failures); }
    size_t current() noexcept { return static_cast<size_t>(read(live_bytes)); }
    size_t peak() noexcept { return static_cast<size_t>(read(peak_bytes)); }
    size_t limit() const noexcept { return maximum; }
    uint64_t allocation_failures() noexcept { return read(failures); }
    bool exhausted() noexcept { return allocation_failures() != 0; }
    ah_memory_budget(const ah_memory_budget &) = delete;
    ah_memory_budget &operator=(const ah_memory_budget &) = delete;
};

static ah_memory_budget *ah_memory_active_budget = nullptr;
class ah_memory_scope final {
    ah_memory_budget *previous;
public:
    ah_memory_budget budget;
    explicit ah_memory_scope(size_t limit = 0) noexcept : previous(ah_memory_active_budget), budget(limit) { ah_memory_active_budget = &budget; }
    ~ah_memory_scope() { ah_memory_active_budget = previous; }
    ah_memory_scope(const ah_memory_scope &) = delete;
    ah_memory_scope &operator=(const ah_memory_scope &) = delete;
};

struct alignas(16) ah_memory_header {
    ah_memory_budget *owner;
    size_t charged;
};
static_assert(sizeof(ah_memory_header) % 16 == 0, "Heap allocation payloads preserve Windows alignment");

static void *ah_memory_allocate(size_t bytes) noexcept {
    ah_memory_budget *owner = ah_memory_active_budget;
    size_t charged = 0;
    if (!ah_size_add(bytes, sizeof(ah_memory_header), charged)) { if (owner) owner->note_failure(); return nullptr; }
    if (owner && !owner->reserve(charged)) return nullptr;
    auto *header = static_cast<ah_memory_header *>(KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, charged));
    if (!header) { if (owner) { owner->release(charged); owner->note_failure(); } return nullptr; }
    header->owner = owner;
    header->charged = charged;
    return header + 1;
}
static void *ah_memory_reallocate(void *memory, size_t bytes) noexcept {
    if (!memory) return ah_memory_allocate(bytes);
    auto *header = static_cast<ah_memory_header *>(memory) - 1;
    ah_memory_budget *owner = header->owner;
    const size_t previous = header->charged;
    size_t charged = 0;
    if (!ah_size_add(bytes, sizeof(ah_memory_header), charged)) { if (owner) owner->note_failure(); return nullptr; }
    const size_t growth = charged > previous ? charged - previous : 0;
    if (owner && growth && !owner->reserve(growth)) return nullptr;
    auto *replacement = static_cast<ah_memory_header *>(KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, header, charged));
    if (!replacement) { if (owner) { if (growth) owner->release(growth); owner->note_failure(); } return nullptr; }
    replacement->owner = owner;
    replacement->charged = charged;
    if (owner && charged < previous) owner->release(previous - charged);
    return replacement + 1;
}
static void ah_memory_release(void *memory) noexcept {
    if (!memory) return;
    auto *header = static_cast<ah_memory_header *>(memory) - 1;
    ah_memory_budget *owner = header->owner;
    const size_t charged = header->charged;
    if (KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, header)) { if (owner) owner->release(charged); }
    else if (owner) owner->note_failure();
}
