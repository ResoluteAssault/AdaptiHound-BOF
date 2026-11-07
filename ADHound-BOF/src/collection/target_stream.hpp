#pragma once

class ah_target_stream final {
    HANDLE file = INVALID_HANDLE_VALUE;
    const unsigned char *memory = nullptr;
    size_t memory_size = 0, memory_offset = 0;
    unsigned char *block = nullptr;
    unsigned char prefix[4] = {};
    size_t used = 0, offset = 0, prefix_size = 0, prefix_offset = 0;
    unsigned int encoding = 8;
    int pending_byte = -1, pending_unit = -1, pending_point = -1;
    bool ended = false, error = false, allocation_error = false;
    int raw() {
        if (pending_byte >= 0) { int value = pending_byte; pending_byte = -1; return value; }
        if (prefix_offset < prefix_size) return prefix[prefix_offset++];
        if (memory) return memory_offset < memory_size ? memory[memory_offset++] : -1;
        if (ended || error || file == INVALID_HANDLE_VALUE) return -1;
        if (offset == used) {
            DWORD count = 0;
            if (!KERNEL32$ReadFile(file, block, 65536, &count, nullptr)) { error = true; return -1; }
            offset = 0; used = count;
            if (!used) { ended = true; return -1; }
        }
        return block[offset++];
    }
    int unit() {
        if (pending_unit >= 0) { int value = pending_unit; pending_unit = -1; return value; }
        int a = raw(), b = raw();
        if (a < 0) return -1;
        if (b < 0) return 0xfffd;
        return encoding == 16 ? a | (b << 8) : (a << 8) | b;
    }
    int point() {
        if (pending_point >= 0) { int value = pending_point; pending_point = -1; return value; }
        if (encoding == 16 || encoding == 17) {
            int value = unit();
            if (value < 0 || value < 0xd800 || value > 0xdfff) return value;
            if (value >= 0xdc00) return 0xfffd;
            int low = unit();
            if (low < 0xdc00 || low > 0xdfff) { pending_unit = low; return 0xfffd; }
            return 0x10000 + ((value - 0xd800) << 10) + low - 0xdc00;
        }
        int first = raw();
        if (first < 0) return -1;
        if (encoding == 32 || encoding == 33) {
            int b = raw(), c = raw(), d = raw();
            if (b < 0 || c < 0 || d < 0) return 0xfffd;
            uint32_t value = encoding == 32 ? static_cast<uint32_t>(first) | static_cast<uint32_t>(b) << 8 | static_cast<uint32_t>(c) << 16 | static_cast<uint32_t>(d) << 24 :
                static_cast<uint32_t>(first) << 24 | static_cast<uint32_t>(b) << 16 | static_cast<uint32_t>(c) << 8 | static_cast<uint32_t>(d);
            return value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff) ? 0xfffd : static_cast<int>(value);
        }
        if (first < 0x80) return first;
        unsigned int extra = first >= 0xc2 && first <= 0xdf ? 1 : first >= 0xe0 && first <= 0xef ? 2 : first >= 0xf0 && first <= 0xf4 ? 3 : 0;
        if (!extra) return 0xfffd;
        uint32_t value = static_cast<uint32_t>(first & (0x7fU >> extra));
        for (unsigned int i = 0; i < extra; ++i) {
            int next = raw();
            if (next < 0 || (next & 0xc0) != 0x80) { pending_byte = next; return 0xfffd; }
            if (i == 0 && ((first == 0xe0 && next < 0xa0) || (first == 0xed && next >= 0xa0) ||
                (first == 0xf0 && next < 0x90) || (first == 0xf4 && next >= 0x90))) { pending_byte = next; return 0xfffd; }
            value = (value << 6) | static_cast<unsigned int>(next & 63);
        }
        const uint32_t minimum[] = {0, 0x80, 0x800, 0x10000};
        return value < minimum[extra] || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff) ? 0xfffd : static_cast<int>(value);
    }
    static void append(ah_buffer &line, unsigned int value) {
        char out[4]; size_t count = 0;
        if (value < 0x80) out[count++] = static_cast<char>(value);
        else if (value < 0x800) { out[count++] = static_cast<char>(0xc0 | value >> 6); out[count++] = static_cast<char>(0x80 | (value & 63)); }
        else if (value < 0x10000) { out[count++] = static_cast<char>(0xe0 | value >> 12); out[count++] = static_cast<char>(0x80 | ((value >> 6) & 63)); out[count++] = static_cast<char>(0x80 | (value & 63)); }
        else { out[count++] = static_cast<char>(0xf0 | value >> 18); out[count++] = static_cast<char>(0x80 | ((value >> 12) & 63)); out[count++] = static_cast<char>(0x80 | ((value >> 6) & 63)); out[count++] = static_cast<char>(0x80 | (value & 63)); }
        ah_append(&line, out, count);
    }
    void detect() {
        unsigned char first[4]; size_t count = 0;
        while (count < sizeof(first)) { int value = raw(); if (value < 0) break; first[count++] = static_cast<unsigned char>(value); }
        size_t skip = 0;
        if (count >= 4 && first[0] == 0xff && first[1] == 0xfe && first[2] == 0 && first[3] == 0) { encoding = 32; skip = 4; }
        else if (count >= 4 && first[0] == 0 && first[1] == 0 && first[2] == 0xfe && first[3] == 0xff) { encoding = 33; skip = 4; }
        else if (count >= 2 && first[0] == 0xff && first[1] == 0xfe) { encoding = 16; skip = 2; }
        else if (count >= 2 && first[0] == 0xfe && first[1] == 0xff) { encoding = 17; skip = 2; }
        else if (count >= 3 && first[0] == 0xef && first[1] == 0xbb && first[2] == 0xbf) skip = 3;
        for (size_t i = skip; i < count; ++i) prefix[prefix_size++] = first[i];
    }
public:
    explicit ah_target_stream(const char *path, const char *inline_text = nullptr) {
        if (inline_text) { memory = reinterpret_cast<const unsigned char *>(inline_text); memory_size = ah_len(inline_text); }
        else {
            block = ah_alloc<unsigned char>(65536);
            if (!block) { error = allocation_error = true; return; }
            wchar_t *wide = ah_wide(path);
            if (!wide) { error = allocation_error = true; return; }
            file = wide ? KERNEL32$CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr) : INVALID_HANDLE_VALUE;
            ah_free(wide); if (file == INVALID_HANDLE_VALUE) { error = true; return; }
        }
        detect();
    }
    ~ah_target_stream() { if (file != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(file); ah_free(block); }
    bool next(ah_buffer &line) {
        line.length = 0;
        if (error) return false;
        bool any = false;
        for (;;) {
            int value = point();
            if (value < 0) { if (!any || error) return false; break; }
            any = true;
            if (value == '\r') { int next = point(); if (next != '\n') pending_point = next; break; }
            if (value == '\n') break;
            append(line, static_cast<unsigned int>(value));
            if (line.failed) { error = allocation_error = true; return false; }
        }
        AH_TEXT(&line, "\0");
        if (line.failed) { error = allocation_error = true; return false; }
        return true;
    }
    bool failed() const { return error; }
    bool no_memory() const { return allocation_error; }
    ah_target_stream(const ah_target_stream &) = delete;
    ah_target_stream &operator=(const ah_target_stream &) = delete;
};
