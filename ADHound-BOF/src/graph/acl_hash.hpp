#pragma once

static char *ah_lower_copy(ah_arena &arena, const char *text) {
    char *out = arena.copy(text);
    if (out) for (char *p = out; *p; ++p) *p = ah_lower(*p);
    return out;
}

static char *ah_rights_text(ah_arena &arena, uint32_t mask) {

    struct right_name { uint32_t flag; const char *name; };
    static const right_name names[] = {
        {0x1, "CreateChild"}, {0x2, "DeleteChild"}, {0x4, "ListChildren"}, {0x8, "Self"},
        {0x10, "ReadProperty"}, {0x20, "WriteProperty"}, {0x40, "DeleteTree"}, {0x80, "ListObject"},
        {0x100, "ExtendedRight"}, {0x10000, "Delete"}, {0x20000, "ReadControl"},
        {0x20004, "GenericExecute"}, {0x20028, "GenericWrite"}, {0x20094, "GenericRead"},
        {0x40000, "WriteDacl"}, {0x80000, "WriteOwner"}, {0xf01ff, "GenericAll"},
        {0x100000, "Synchronize"}, {0x1000000, "AccessSystemSecurity"}
    };
    bool selected[sizeof(names) / sizeof(names[0])] = {};
    uint32_t remaining = mask;
    for (size_t i = sizeof(names) / sizeof(names[0]); i; --i) if ((remaining & names[i - 1].flag) == names[i - 1].flag) {
        selected[i - 1] = true; remaining &= ~names[i - 1].flag;
    }
    ah_buffer out(512); bool first = true;
    if (remaining || !mask) {
        int64_t value = static_cast<int32_t>(mask);
        if (value < 0) { AH_TEXT(&out, "-"); value = -value; }
        char digits[32]; const char *number = ah_decimal(digits + sizeof(digits), static_cast<uint64_t>(value));
        ah_append(&out, number, ah_len(number));
    } else for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) if (selected[i]) {
        if (!first) { AH_TEXT(&out, ", "); }
        first = false; ah_append(&out, names[i].name, ah_len(names[i].name));
    }
    AH_TEXT(&out, "\0");
    return out.failed ? nullptr : arena.copy(out.data);
}

static char *ah_hash_text(ah_arena &arena, const char *text) {
    ah_value value = {const_cast<char *>(text), ah_len(text), nullptr};
    return ah_thumbprint(arena, &value);
}
static const char *ah_hash_guid(const char *value) {
    return *value ? value : "00000000-0000-0000-0000-000000000000";
}

static char *ah_inheritance_hash(ah_arena &arena, const ah_ace &ace) {
    ah_buffer text(1024);
    ah_append(&text, ace.sid, ah_len(ace.sid));
    char *rights = ah_rights_text(arena, ace.mask);
    ah_append(&text, rights, ah_len(rights));
    const char *property = ah_hash_guid(ace.property), *inherited = ah_hash_guid(ace.inherited_class);
    ah_append(&text, property, ah_len(property));
    ah_append(&text, inherited, ah_len(inherited));
    AH_TEXT(&text, "\0");
    return ah_hash_text(arena, text.data);
}

static void ah_inheritance_hashes(ah_graph &g, ah_buffer &b, ah_value *descriptor) {
    AH_TEXT(&b, "["); bool first = true;
    if (!ah_ad_rule_aces(descriptor, [&](const ah_ace &ace) {
        if (ace.type == 1 || ace.type == 6 || (ace.flags & 0x10) || !(ace.flags & 3) ||
            ah_eq(ace.sid, "S-1-5-18") || ah_eq(ace.sid, "S-1-3-0") || ah_eq(ace.sid, "S-1-5-10")) return;
        if (!first) { AH_TEXT(&b, ","); }
        first = false; ah_string(b, ah_inheritance_hash(g.arena, ace));
    })) b.failed = true;
    AH_TEXT(&b, "]");
}

static const char *ah_inheritance_flags_text(unsigned char flags) {
    if ((flags & 3) == 1) return "ObjectInherit";
    if ((flags & 3) == 2) return "ContainerInherit";
    if ((flags & 3) == 3) return "ContainerInherit, ObjectInherit";
    return "None";
}

static int ah_hash_ace_compare(const ah_ace *a, const ah_ace *b) {
    unsigned char at = a->type == 1 || a->type == 6, bt = b->type == 1 || b->type == 6;
    if (at != bt) return at - bt;
    size_t sid_index = 0;
    for (; a->sid[sid_index] && b->sid[sid_index]; ++sid_index) if (a->sid[sid_index] != b->sid[sid_index]) return static_cast<unsigned char>(a->sid[sid_index]) - static_cast<unsigned char>(b->sid[sid_index]);
    if (a->sid[sid_index] != b->sid[sid_index]) return static_cast<unsigned char>(a->sid[sid_index]) - static_cast<unsigned char>(b->sid[sid_index]);
    if (a->mask != b->mask) return static_cast<int32_t>(a->mask) < static_cast<int32_t>(b->mask) ? -1 : 1;
    const char *ap = ah_hash_guid(a->property), *bp = ah_hash_guid(b->property);
    for (size_t i = 0; i < 36; ++i) if (ap[i] != bp[i]) return ap[i] - bp[i];
    ap = ah_hash_guid(a->inherited_class); bp = ah_hash_guid(b->inherited_class);
    for (size_t i = 0; i < 36; ++i) if (ap[i] != bp[i]) return ap[i] - bp[i];
    unsigned int af = ((a->flags & 1) ? 2 : 0) | ((a->flags & 2) ? 1 : 0);
    unsigned int bf = ((b->flags & 1) ? 2 : 0) | ((b->flags & 2) ? 1 : 0);
    return static_cast<int>(af) - static_cast<int>(bf);
}

static char *ah_implicit_acl_hash(ah_graph &g, ah_value *descriptor) {
    if (!descriptor) return nullptr;
    size_t count = 0;
    if (!ah_ad_rule_aces(descriptor, [&](const ah_ace &) { ++count; })) return nullptr;
    if (!count) return nullptr;
    ah_ace *items = static_cast<ah_ace *>(g.arena.alloc(count * sizeof(ah_ace)));
    if (!items) return nullptr;
    size_t used = 0;
    ah_ad_rule_aces(descriptor, [&](const ah_ace &ace) { if (!(ace.flags & 0x10)) items[used++] = ace; });
    if (!used) return nullptr;
    for (size_t i = 0; i < used; ++i) for (size_t j = i + 1; j < used; ++j) if (ah_hash_ace_compare(&items[i], &items[j]) > 0) {
        ah_ace swap = items[i]; items[i] = items[j]; items[j] = swap;
    }
    ah_buffer text(4 * 1024 * 1024);
    for (size_t i = 0; i < used; ++i) {
        const ah_ace &ace = items[i];
        if (i) AH_TEXT(&text, ";");
        ah_append(&text, ace.sid, ah_len(ace.sid)); AH_TEXT(&text, "|");
        char *rights = ah_rights_text(g.arena, ace.mask); ah_append(&text, rights, ah_len(rights)); AH_TEXT(&text, "|");
        const char *access = ace.type == 1 || ace.type == 6 ? "Deny" : "Allow";
        ah_append(&text, access, ah_len(access)); AH_TEXT(&text, "|");
        char *object = ah_lower_copy(g.arena, ah_hash_guid(ace.property)); ah_append(&text, object, ah_len(object)); AH_TEXT(&text, "|");
        char *inherited = ah_lower_copy(g.arena, ah_hash_guid(ace.inherited_class)); ah_append(&text, inherited, ah_len(inherited)); AH_TEXT(&text, "|");
        const char *flags = ah_inheritance_flags_text(ace.flags); ah_append(&text, flags, ah_len(flags));
    }
    bool protected_dacl = descriptor->size >= 20 && (ah_u16(reinterpret_cast<unsigned char *>(descriptor->data) + 2) & 0x1000);
    AH_TEXT(&text, "|DaclProtected:"); if (protected_dacl) AH_TEXT(&text, "True"); else AH_TEXT(&text, "False");
    AH_TEXT(&text, "\0");
    return text.failed ? nullptr : ah_hash_text(g.arena, text.data);
}

static int ah_admin_sdholder_protected(ah_graph &g, ah_object *o) {
    ah_object *holder = g.dns.find(ah_concat(g.arena, "CN=AdminSDHolder,CN=System,", g.root->dn));
    if (!holder || !o->values("nTSecurityDescriptor")) return -1;
    char *expected = ah_implicit_acl_hash(g, holder->values("nTSecurityDescriptor"));
    char *actual = ah_implicit_acl_hash(g, o->values("nTSecurityDescriptor"));
    if (!expected || !actual) return -1;
    return ah_eq(expected, actual) ? 1 : 0;
}

static bool ah_raw_owner_rights(ah_object *o, bool inherited) {
    bool found = false;
    ah_sd_aces(o->values("nTSecurityDescriptor"), [&](const ah_ace &ace) {
        if (ace.type != 1 && ace.type != 6 && ah_eq(ace.sid, "S-1-3-4") && ((ace.flags & 0x10) != 0) == inherited) found = true;
    });
    return found;
}
