#pragma once

static inline unsigned int ah_timespan_space(const char *text) {
    const auto *p = reinterpret_cast<const unsigned char *>(text);
    if ((p[0] >= 9 && p[0] <= 13) || p[0] == 32) return 1;
    if (!p[0] || !p[1]) return 0;
    if (p[0] == 0xc2 && (p[1] == 0x85 || p[1] == 0xa0)) return 2;
    if (!p[2]) return 0;
    if ((p[0] == 0xe1 && p[1] == 0x9a && p[2] == 0x80) ||
        (p[0] == 0xe2 && p[1] == 0x80 && ((p[2] >= 0x80 && p[2] <= 0x8a) || p[2] == 0xa8 || p[2] == 0xa9 || p[2] == 0xaf)) ||
        (p[0] == 0xe2 && p[1] == 0x81 && p[2] == 0x9f) || (p[0] == 0xe3 && p[1] == 0x80 && p[2] == 0x80)) return 3;
    return 0;
}
static inline bool ah_timespan_parse(const char *text, int64_t &ticks, bool integer_seconds = false) {
    if (!text) return false;
    while (unsigned int whitespace = ah_timespan_space(text)) text += whitespace;
    bool negative = *text == '-';
    if (*text == '+' && !integer_seconds) return false;
    if (negative || *text == '+') ++text;
    uint64_t parts[5] = {}; char separators[4] = {}; unsigned int count = 0;
    const char *cursor = text;
    for (;;) {
        if (*cursor == '.' && count >= 2 && count < 4 && separators[count - 1] == ':') {
            parts[count++] = 0; separators[count - 1] = *cursor++; continue;
        }
        if (count == 5 || *cursor < '0' || *cursor > '9') return false;
        uint64_t value = 0;
        do {
            unsigned int digit = static_cast<unsigned int>(*cursor++ - '0');
            if (value > (UINT64_MAX - digit) / 10) return false;
            value = value * 10 + digit;
        } while (*cursor >= '0' && *cursor <= '9');
        parts[count++] = value;
        if (*cursor != ':' && *cursor != '.') break;
        if (count == 5) return false;
        separators[count - 1] = *cursor++;
    }
    while (unsigned int whitespace = ah_timespan_space(cursor)) cursor += whitespace;
    if (*cursor) return false;
    if (integer_seconds && count != 1) return false;
    uint64_t days = 0, hours = 0, minutes = 0, seconds = 0, fraction = 0;
    unsigned int fraction_part = 5;
    if (count == 1) { if (integer_seconds) seconds = parts[0]; else days = parts[0]; }
    else if (count == 2 && separators[0] == ':') { hours = parts[0]; minutes = parts[1]; }
    else if (count == 3 && separators[0] == '.' && separators[1] == ':') { days = parts[0]; hours = parts[1]; minutes = parts[2]; }
    else if ((count == 3 || count == 4) && separators[0] == ':' && separators[1] == ':' && (count == 3 || separators[2] == '.')) {
        hours = parts[0]; minutes = parts[1]; seconds = parts[2];
        if (count == 4) fraction_part = 3;

        if (hours > 23 && count == 3 && parts[1] <= 23 && parts[2] <= 59) { days = parts[0]; hours = parts[1]; minutes = parts[2]; seconds = 0; }
    } else if ((count == 4 || count == 5) && (separators[0] == '.' || separators[0] == ':') && separators[1] == ':' && separators[2] == ':' && (count == 4 || separators[3] == '.')) {
        days = parts[0]; hours = parts[1]; minutes = parts[2]; seconds = parts[3];
        if (count == 5) fraction_part = 4;
    } else return false;
    if (hours > 23 || minutes > 59 || (count != 1 && seconds > 59)) return false;
    if (fraction_part != 5) {

        const char *token = text;
        for (unsigned int i = 0; i < fraction_part; ++i) { while (*token >= '0' && *token <= '9') ++token; ++token; }
        unsigned int digits = 0; const char *p = token;
        while (*p >= '0' && *p <= '9') { ++p; ++digits; }
        if (!digits || parts[fraction_part] > 9999999) return false;
        fraction = parts[fraction_part];

        if (digits > 14) fraction = 0;
        else while (digits > 7) { fraction /= 10; --digits; }
        while (digits++ < 7) fraction *= 10;
    }
    const uint64_t maximum = negative ? (1ULL << 63) : static_cast<uint64_t>(INT64_MAX);
    uint64_t total = 0;
    const uint64_t values[] = {days, hours, minutes, seconds, fraction};
    const uint64_t scales[] = {864000000000ULL, 36000000000ULL, 600000000ULL, 10000000ULL, 1ULL};
    for (unsigned int i = 0; i < 5; ++i) {
        if (values[i] > (maximum - total) / scales[i]) return false;
        total += values[i] * scales[i];
    }
    ticks = negative ? (total == (1ULL << 63) ? INT64_MIN : -static_cast<int64_t>(total)) : static_cast<int64_t>(total);
    return true;
}

static inline uint64_t ah_timespan_milliseconds(int64_t ticks) {
    return ticks > 0 ? static_cast<uint64_t>(ticks) / 10000ULL : 0;
}

static inline bool ah_timespan_timer_interval(int64_t ticks, uint32_t &milliseconds) {
    if (ticks <= 0 || static_cast<uint64_t>(ticks) > static_cast<uint64_t>(INT32_MAX) * 10000ULL) return false;
    milliseconds = static_cast<uint32_t>((static_cast<uint64_t>(ticks) + 9999ULL) / 10000ULL);
    return true;
}

static inline bool ah_timespan_finite_delay(int64_t ticks, uint32_t &milliseconds) {

    if (ticks <= -10000LL) return false;
    const uint64_t value = ah_timespan_milliseconds(ticks);
    if (value > static_cast<uint64_t>(INT32_MAX)) return false;
    milliseconds = static_cast<uint32_t>(value);
    return true;
}
