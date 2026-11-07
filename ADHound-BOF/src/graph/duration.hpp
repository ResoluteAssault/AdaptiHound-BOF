#pragma once

static const char *ah_adcs_duration(ah_arena &arena, const ah_object *o, const char *name) {
    ah_value *value = o->values(name);
    if (!value || !value->size || value->size > 8) return "Unknown";
    uint64_t raw_ticks = 0;
    for (size_t i = 0; i < value->size; ++i) raw_ticks |= static_cast<uint64_t>(static_cast<unsigned char>(value->data[i])) << (i * 8);
    int64_t signed_ticks = static_cast<int64_t>(raw_ticks);
    if (signed_ticks >= 0) return "";
    uint64_t ticks = static_cast<uint64_t>(-(signed_ticks + 1)) + 1;
    char result[64];
    size_t pos = 0;
    auto append = [&](const char *text) {
        for (size_t i = 0; text[i] && pos + 1 < sizeof(result); ++i) result[pos++] = text[i];
    };
    uint64_t number = 0;
    const char *unit = nullptr;
    const uint64_t periods[] = {31536000ULL, 2592000ULL, 604800ULL, 86400ULL, 3600ULL};
    const char *units[] = {"year", "month", "week", "day", "hour"};
    for (size_t i = 0; i < sizeof(periods) / sizeof(periods[0]); ++i) {
        uint64_t period = periods[i] * 10000000ULL;
        if (ticks >= period && ticks % period == 0) { number = ticks / period; unit = units[i]; break; }
    }
    if (!unit) return "";
    char digits[32]; const char *decimal = ah_decimal(digits + sizeof(digits), number);
    append(decimal); append(" "); append(unit); if (number != 1) append("s");
    result[pos] = 0;
    return arena.copy(result, pos);
}

static const char *ah_domain_duration(ah_arena &arena, const ah_object *o, const char *name) {
    ah_value *value = o->values(name);
    if (!value) return "";
    int64_t ticks = ah_integer(value);
    if (ticks == (-9223372036854775807LL - 1)) return "Forever";
    if (ticks > 0) return "";
    uint64_t seconds = ticks < 0 ? static_cast<uint64_t>(-(ticks + 1)) + 1 : static_cast<uint64_t>(ticks);
    seconds /= 10000000ULL;
    char result[128]; size_t pos = 0;
    auto component = [&](uint64_t number, const char *unit) {
        if (!number) return;
        if (pos) { result[pos++] = ','; result[pos++] = ' '; }
        char digits[32]; const char *decimal = ah_decimal(digits + sizeof(digits), number);
        for (const char *p = decimal; *p && pos + 1 < sizeof(result); ++p) result[pos++] = *p;
        result[pos++] = ' ';
        for (const char *p = unit; *p && pos + 1 < sizeof(result); ++p) result[pos++] = *p;
        if (number != 1 && pos + 1 < sizeof(result)) result[pos++] = 's';
    };
    component(seconds / 86400, "day");
    component(seconds % 86400 / 3600, "hour");
    component(seconds % 3600 / 60, "minute");
    component(seconds % 60, "second");
    result[pos] = 0;
    return arena.copy(result, pos);
}
