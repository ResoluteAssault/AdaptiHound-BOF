#pragma once

static bool ah_ipa_one_of(const char *name, const char *const *names, size_t count) {
    for (size_t i = 0; i < count; ++i) if (ah_eq(name, names[i])) return true;
    return false;
}

static void ah_ipa_bytes_repr(ah_buffer &out, ah_value *values) {
    ah_buffer bytes(0, 128), repr(0, 128);
    for (ah_value *v = values; v; v = v->next) {
        if (v != values) AH_TEXT(&bytes, "\n");
        ah_append(&bytes, v->data, v->size);
    }
    bool single = false, dual = false;
    for (size_t i = 0; i < bytes.length; ++i) { single |= bytes.data[i] == '\''; dual |= bytes.data[i] == '"'; }
    const char quote = single && !dual ? '"' : '\'';
    AH_TEXT(&repr, "b"); ah_append(&repr, &quote, 1);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < bytes.length; ++i) {
        const char raw = bytes.data[i];
        const unsigned char c = static_cast<unsigned char>(raw);
        if (c == static_cast<unsigned char>(quote) || c == '\\') { AH_TEXT(&repr, "\\"); ah_append(&repr, &raw, 1); }
        else if (c == '\t') AH_TEXT(&repr, "\\t");
        else if (c == '\n') AH_TEXT(&repr, "\\n");
        else if (c == '\r') AH_TEXT(&repr, "\\r");
        else if (c < 32 || c >= 127) { const char escaped[] = {'\\', 'x', hex[c >> 4], hex[c & 15]}; ah_append(&repr, escaped, sizeof(escaped)); }
        else ah_append(&repr, &raw, 1);
    }
    ah_append(&repr, &quote, 1);
    if (bytes.failed || repr.failed) out.failed = true;
    else ah_json_bytes(&out, repr.data, repr.length);
}

static bool ah_ipa_datetime(ah_buffer &out, const ah_value *value) {
    if (value->size < 14) return false;
    for (size_t i = 0; i < 14; ++i) if (value->data[i] < '0' || value->data[i] > '9') return false;
    const char *s = value->data;
    const char formatted[] = {s[8], s[9], ':', s[10], s[11], ':', s[12], s[13], ' ', s[6], s[7], '.', s[4], s[5], '.', s[0], s[1], s[2], s[3]};
    ah_json_bytes(&out, formatted, sizeof(formatted));
    return true;
}

static void ah_ipa_property(ah_buffer &out, const ah_attr *attribute) {
    static const char *const integers[] = {"uidNumber", "gidNumber", "krbTicketFlags", "krbLoginFailedCount", "ipaCaRandomSerialNumberVersion"};
    static const char *const booleans[] = {"ipaEnabledFlag", "ipaCertProfileStoreIssued"};
    static const char *const dates[] = {"krbPrincipalExpiration", "krbPasswordExpiration", "krbLastPwdChange", "krbLastAdminUnlock"};
    const ah_value *value = attribute->values;
    if (ah_eq(attribute->name, "krbExtraData")) { ah_ipa_bytes_repr(out, attribute->values); return; }
    if (!value->next) {
        if (ah_ipa_one_of(attribute->name, integers, sizeof(integers) / sizeof(*integers))) { ah_int64(out, ah_signed(value->data)); return; }
        if (ah_ipa_one_of(attribute->name, booleans, sizeof(booleans) / sizeof(*booleans))) {
            if (ah_eq(value->data, "TRUE")) AH_TEXT(&out, "true"); else AH_TEXT(&out, "false");
            return;
        }
        if (ah_ipa_one_of(attribute->name, dates, sizeof(dates) / sizeof(*dates)) && ah_ipa_datetime(out, value)) return;
        ah_json_bytes(&out, value->data, value->size);
        return;
    }
    ah_buffer joined(0, 128);
    for (const ah_value *v = value; v; v = v->next) {
        if (v != value) AH_TEXT(&joined, "\n");
        ah_append(&joined, v->data, v->size);
    }
    if (joined.failed) out.failed = true; else ah_json_bytes(&out, joined.data, joined.length);
}

static void ah_ipa_optional_text(ah_fields &fields, const char *key, const ah_object *object, const char *attribute) {
    if (object->values(attribute)) fields.text(key, object->text(attribute));
}

static void ah_ipa_rule_properties(ah_buffer &out, ah_fields &fields, const ah_object *rule, bool sudo) {
    ah_ipa_optional_text(fields, "rule_name", rule, "cn");
    ah_ipa_optional_text(fields, "rule_description", rule, "description");
    if (!sudo) ah_ipa_optional_text(fields, "rule_type", rule, "accessRuleType");
    if (rule->values("ipaEnabledFlag")) fields.boolean("rule_enabled", ah_eq(rule->text("ipaEnabledFlag"), "TRUE"));
    const char *attributes[] = {"userCategory", "hostCategory", sudo ? "cmdCategory" : "serviceCategory"};
    const char *keys[] = {"user_category", "host_category", sudo ? "cmd_category" : "service_category"};
    for (size_t i = 0; i < 3; ++i) if (ah_eq(rule->text(attributes[i]), "all")) fields.text(keys[i], "all");
    if (!sudo) return;
    const char *extra[] = {"ipaSudoRunAsUser", "ipaSudoRunAsGroup", "ipaSudoOption"};
    const char *names[] = {"run_as_user", "run_as_group", "sudo_options"};
    for (size_t i = 0; i < 3; ++i) if (ah_value *values = rule->values(extra[i])) {
        fields.key(names[i]);
        if (values->next) ah_text_array(out, values); else ah_string(out, values->data);
    }
}
