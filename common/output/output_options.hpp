#pragma once
#include "../core/settings.hpp"
#include "../core/native_api.hpp"

static bool ah_output_random(unsigned char *output, size_t size) {
    if (size > 0xffffffffULL) return false;
    ah_native_library bcrypt(L"bcrypt.dll");
    using generate_type = LONG (WINAPI *)(void *, unsigned char *, ULONG, ULONG);
    auto generate = bcrypt.find<generate_type>("BCryptGenRandom");
    return generate && generate(nullptr, output, static_cast<ULONG>(size), 2) >= 0;
}
static bool ah_output_system_time(SYSTEMTIME &value) {
    ah_native_library kernel(L"kernel32.dll");
    auto query = kernel.find<decltype(&GetLocalTime)>("GetLocalTime");
    if (!query) return false;
    query(&value); return true;
}
static bool ah_output_timestamp(char (&output)[16]) {
    SYSTEMTIME time = {};
    if (!ah_output_system_time(time)) return false;
    const unsigned int values[] = {time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond};
    const unsigned int widths[] = {4, 2, 2, 2, 2, 2};
    size_t position = 0;
    for (unsigned int i = 0; i < 6; ++i) {
        unsigned int divisor = widths[i] == 4 ? 1000 : 10;
        for (unsigned int n = 0; n < widths[i]; ++n, divisor /= 10)
            output[position++] = static_cast<char>('0' + values[i] / divisor % 10);
    }
    output[position] = 0;
    return true;
}
static char *ah_output_name(ah_arena &arena, const char *base, const char *extension, const char *timestamp) {
    const char *name = base;
    if (ah_random_filenames && (ah_eq(extension,"json") || ah_eq(extension,"zip"))) {
        unsigned char random[11];
        if (!ah_output_random(random, sizeof(random))) { arena.failed = true; return nullptr; }
        static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz012345";
        char generated[13];
        for (unsigned int i = 0; i < 8; ++i) generated[i] = alphabet[random[i] & 31];
        generated[8] = '.';
        for (unsigned int i = 0; i < 3; ++i) generated[9 + i] = alphabet[random[8 + i] & 31];
        generated[12] = 0;
        name = arena.copy(generated);
    } else if (extension && *extension) {
        size_t length = ah_len(base), suffix = ah_len(extension);
        bool present = length >= suffix;
        for (size_t i = 0; present && i < suffix; ++i) if (base[length - suffix + i] != extension[i]) present = false;
        if (!present) name = ah_concat(arena, base, ".", extension);
    }
    if (timestamp && *timestamp) name = ah_concat(arena, timestamp, "_", name);
    if (ah_output_prefix && *ah_output_prefix) name = ah_concat(arena, ah_output_prefix, "_", name);
    return name ? arena.copy(name) : nullptr;
}
static bool ah_pretty_json(ah_buffer &json) {
    ah_buffer formatted(json.limit);
    bool quoted = false, escaped = false;
    unsigned int depth = 0;
    auto indentation = [&]() {
        AH_TEXT(&formatted, "\n");
        for (unsigned int i = 0; i < depth; ++i) AH_TEXT(&formatted, "  ");
    };
    for (size_t i = 0; i < json.length && !formatted.failed; ++i) {
        char c = json.data[i];
        if (quoted) {
            ah_append(&formatted, &c, 1);
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
            continue;
        }
        if (c == '"') quoted = true;
        else if (c == '{' || c == '[') {
            ah_append(&formatted, &c, 1);
            if (++depth > 256) return false;
            char next = i + 1 < json.length ? json.data[i + 1] : 0;
            if (next != '}' && next != ']') indentation();
            continue;
        } else if (c == '}' || c == ']') {
            if (!depth) return false;
            --depth;
            char previous = i ? json.data[i - 1] : 0;
            if (previous != '{' && previous != '[') indentation();
        } else if (c == ',') {
            ah_append(&formatted, &c, 1); indentation(); continue;
        } else if (c == ':') {
            AH_TEXT(&formatted, ": "); continue;
        } else if (static_cast<unsigned char>(c) <= 32) continue;
        ah_append(&formatted, &c, 1);
    }
    if (formatted.failed || depth || quoted) return false;
    char *previous = json.data;
    json.data = formatted.data; json.length = formatted.length; json.capacity = formatted.capacity;
    formatted.data = previous;
    return true;
}
