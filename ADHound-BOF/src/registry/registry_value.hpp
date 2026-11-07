#pragma once

static bool ah_registry_unsigned_text(const wchar_t *text, uint64_t maximum, uint64_t &number) {
    if (!text) return false;
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') ++text;
    bool negative = *text == '-'; if (negative || *text == '+') ++text;
    if (*text < '0' || *text > '9') return false;
    number = 0;
    while (*text >= '0' && *text <= '9') {
        unsigned int digit = static_cast<unsigned int>(*text++ - '0');
        if (number > (maximum - digit) / 10) return false;
        number = number * 10 + digit;
    }
    while (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n') ++text;
    return !*text && (!negative || number == 0);
}
static char *ah_registry_number_text(ah_arena &arena, uint64_t value, bool is_signed) {
    bool negative = is_signed && (value >> 63);
    uint64_t magnitude = negative ? 0 - value : value;
    char digits[32]; const char *text = ah_decimal(digits + sizeof(digits), magnitude);
    return negative ? ah_concat(arena, "-", text) : arena.copy(text);
}
static bool ah_registry_variant_value(ah_arena &arena, const ah_registry_wmi_query &query, const VARIANT &value) {
    if (query.number) {
        uint64_t number = 0;
        if (query.type == REG_DWORD && (value.vt == VT_I4 || value.vt == VT_UI4)) number = value.ulVal;
        else if (query.type == REG_QWORD && value.vt == VT_UI8) number = value.ullVal;
        else if (query.type == REG_QWORD && value.vt == VT_I8 && value.llVal >= 0) number = static_cast<uint64_t>(value.llVal);
        else if ((query.type == REG_SZ || query.type == REG_EXPAND_SZ || query.type == REG_QWORD) && value.vt == VT_BSTR && value.bstrVal) {
            if (!ah_registry_unsigned_text(value.bstrVal, 0xffffffffULL, number)) return false;
        } else return false;
        if (number > 0xffffffffULL) return false;
        *query.number = static_cast<uint32_t>(number); if (query.valid) *query.valid = true; return true;
    }
    if (!query.text) return false;
    if ((query.type == REG_SZ || query.type == REG_EXPAND_SZ) && value.vt == VT_BSTR && value.bstrVal) *query.text = arena.utf8(value.bstrVal);
    else if (query.type == REG_DWORD && (value.vt == VT_I4 || value.vt == VT_UI4)) *query.text = ah_registry_number_text(arena, value.ulVal, false);
    else if (query.type == REG_QWORD && (value.vt == VT_I8 || value.vt == VT_UI8)) *query.text = ah_registry_number_text(arena, value.ullVal, false);
    else if (query.type == REG_QWORD && value.vt == VT_BSTR && value.bstrVal) *query.text = arena.utf8(value.bstrVal);
    else if (query.type == REG_MULTI_SZ) *query.text = arena.copy("System.String[]");
    else if (query.type == REG_BINARY) *query.text = arena.copy("System.Byte[]");
    else return false;
    if (!*query.text) return false;
    if (query.valid) *query.valid = true;
    return true;
}
