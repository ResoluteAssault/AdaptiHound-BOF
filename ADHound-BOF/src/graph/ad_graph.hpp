#pragma once
#include "sha1.hpp"

struct ah_ace {
    char sid[192], property[37], inherited_class[37];
    uint32_t mask, order;
    unsigned char flags, type;
    const unsigned char *opaque;
    size_t opaque_size;
};
template <typename Visitor>
static bool ah_sd_aces(ah_value *value, Visitor visitor, bool include_callbacks = false) {
    if (!value) return true;
    const unsigned char *p = reinterpret_cast<unsigned char *>(value->data); size_t n = value->size;
    if (n < 20 || p[0] != 1 || !(ah_u16(p + 2) & 0x8000)) return false;
    uint32_t offset = ah_u32(p + 16);
    if (!offset) return true;
    if (offset < 20 || offset > n || n - offset < 8) return false;
    size_t size = ah_u16(p + offset + 2), end = offset + size;
    unsigned int count = ah_u16(p + offset + 4);
    if (size < 8 || end > n) return false;
    offset += 8;
    for (unsigned int i = 0; i < count; ++i) {
        if (offset > end || end - offset < 4) return false;
        size_t length = ah_u16(p + offset + 2);
        if (length < 4 || length > end - offset) return false;
        const unsigned char *a = p + offset; offset += static_cast<uint32_t>(length);
        bool callback = a[0] >= 9 && a[0] <= 12;
        if (a[0] != 0 && a[0] != 1 && a[0] != 5 && a[0] != 6 && !(callback && include_callbacks)) continue;
        if (length < 8) return false;
        ah_ace ace = {}; ace.type = a[0]; ace.flags = a[1]; ace.mask = ah_u32(a + 4); ace.order = i; size_t pos = 8;
        if (a[0] == 5 || a[0] == 6 || a[0] == 11 || a[0] == 12) {
            if (length < 12) return false;
            uint32_t flags = ah_u32(a + 8); pos = 12;
            if (flags & 1) { if (length - pos < 16 || !ah_guid_string(ace.property, a + pos, 16)) return false; pos += 16; }
            if (flags & 2) { if (length - pos < 16 || !ah_guid_string(ace.inherited_class, a + pos, 16)) return false; pos += 16; }
        }
        if (pos > length || length - pos < 2) return false;
        size_t sid_length = 8 + 4 * static_cast<size_t>(a[pos + 1]);
        if (sid_length > length - pos || !ah_sid_string(ace.sid, a + pos, sid_length)) return false;
        ace.opaque = a + pos + sid_length; ace.opaque_size = length - pos - sid_length;
        visitor(ace);
    }
    return true;
}

static bool ah_ad_guid_equal(const char *a, const char *b) {
    const char *zero = "00000000-0000-0000-0000-000000000000";
    return ah_eq(*a ? a : zero, *b ? b : zero);
}
static uint64_t ah_sid_part(const char *&text) {
    uint64_t value = 0;
    while (*text >= '0' && *text <= '9') value = value * 10 + static_cast<unsigned int>(*text++ - '0');
    if (*text == '-') ++text;
    return value;
}
static int ah_ad_sid_compare(const char *a, const char *b) {

    a += 2; b += 2; ah_sid_part(a); ah_sid_part(b);
    uint64_t authority_a = ah_sid_part(a), authority_b = ah_sid_part(b);
    if (authority_a != authority_b) return authority_a < authority_b ? -1 : 1;
    size_t count_a = *a ? 1 : 0, count_b = *b ? 1 : 0;
    for (const char *p = a; *p; ++p) if (*p == '-') ++count_a;
    for (const char *p = b; *p; ++p) if (*p == '-') ++count_b;
    if (count_a != count_b) return count_a < count_b ? -1 : 1;
    while (*a && *b) {
        uint64_t part_a = ah_sid_part(a), part_b = ah_sid_part(b);
        if (part_a != part_b) return part_a < part_b ? -1 : 1;
    }
    return 0;
}
static unsigned int ah_ad_ace_priority(const ah_ace &ace) {
    if (ace.flags & 0x10) return 2 * 65535U + ace.order;
    bool deny = ace.type == 1 || ace.type == 6 || ace.type == 10 || ace.type == 12;
    bool object = ace.type == 5 || ace.type == 6 || ace.type == 11 || ace.type == 12;
    return (deny ? 0U : 2U) + (object ? 1U : 0U);
}
static int ah_ad_canonical_compare(const ah_ace &a, const ah_ace &b) {
    unsigned int ap = ah_ad_ace_priority(a), bp = ah_ad_ace_priority(b);
    return ap == bp ? ah_ad_sid_compare(a.sid, b.sid) : ap < bp ? -1 : 1;
}
static void ah_ad_canonical_sort(ah_ace *items, size_t left, size_t right) {

    while (left < right) {
        size_t low = left, high = right; ah_ace pivot = items[left];
        while (low < high) {
            while (low < high && ah_ad_canonical_compare(items[high], pivot) >= 0) --high;
            if (low != high) items[low++] = items[high];
            while (low < high && ah_ad_canonical_compare(items[low], pivot) <= 0) ++low;
            if (low != high) items[high--] = items[low];
        }
        items[low] = pivot;
        if (low - left < right - low) {
            if (low > left) ah_ad_canonical_sort(items, left, low - 1);
            left = low + 1;
        } else {
            if (low < right) ah_ad_canonical_sort(items, low + 1, right);
            if (low == 0) break;
            right = low - 1;
        }
    }
}
static bool ah_ad_merge_aces(ah_ace &a, const ah_ace &b) {
    if (a.type != b.type || (a.flags & 0x10) || (b.flags & 0x10) || !ah_eq(a.sid, b.sid) || a.opaque_size != b.opaque_size) return false;
    for (size_t i = 0; i < a.opaque_size; ++i) if (a.opaque[i] != b.opaque[i]) return false;
    bool same_property = ah_ad_guid_equal(a.property, b.property), same_inherited = ah_ad_guid_equal(a.inherited_class, b.inherited_class);
    if (a.flags == b.flags && same_inherited &&
        (same_property || (!*a.property && (a.mask & b.mask & 0x13bU) == (b.mask & 0x13bU)))) {
        a.mask |= b.mask; return true;
    }
    if ((a.flags & 0x0f) == (b.flags & 0x0f) && a.mask == b.mask && same_inherited && same_property) return true;
    if (a.mask != b.mask || !same_property || (!same_inherited && *a.inherited_class)) return false;

    auto propagation = [](unsigned char flags) -> unsigned int {
        if (!(flags & 2)) return flags & 8 ? 0U : 1U;
        return (flags & 8 ? 0U : 1U) | (flags & 4 ? 2U : 6U);
    };
    unsigned int ap = propagation(a.flags), bp = propagation(b.flags);
    if (!ap || !bp) return false;
    unsigned int combined = ap | bp;
    a.flags = static_cast<unsigned char>((combined & 6 ? 2 : 0) | ((combined & 6) == 2 ? 4 : 0) | (combined & 1 ? 0 : 8));
    return true;
}
template <typename Visitor>
static bool ah_ad_rule_aces(ah_value *descriptor, Visitor visitor) {
    size_t count = 0;
    if (!ah_sd_aces(descriptor, [&](const ah_ace &) { ++count; }, true)) return false;
    if (!count) return true;
    ah_ace *items = ah_alloc<ah_ace>(count * sizeof(ah_ace)); if (!items) return false;
    struct allocation_guard { ah_ace *value; ~allocation_guard() { ah_free(value); } } guard{items};
    size_t used = 0; unsigned int stage = 0; bool canonical = true;
    if (!ah_sd_aces(descriptor, [&](const ah_ace &raw) {
        if (!raw.mask || ((raw.flags & 8) && !(raw.flags & 3))) return;
        ah_ace ace = raw; ace.flags &= 0x3f;
        if (!(ace.flags & 3)) ace.flags &= static_cast<unsigned char>(~4U);
        unsigned int current = ace.flags & 0x10 ? 2U : ace.type == 1 || ace.type == 6 || ace.type == 10 || ace.type == 12 ? 0U : 1U;
        if (current < stage) canonical = false; else stage = current;
        items[used++] = ace;
    }, true)) return false;
    if (canonical && used) {
        ah_ad_canonical_sort(items, 0, used - 1);
        for (size_t i = 0; i + 1 < used; ++i) if (ah_ad_merge_aces(items[i], items[i + 1])) {
            for (size_t j = i + 1; j + 1 < used; ++j) items[j] = items[j + 1];
            --used;
        }
    }
    for (size_t i = 0; i < used; ++i) {
        ah_ace &ace = items[i]; if (ace.type >= 9 && ace.type <= 12) continue;

        if (!(ace.mask & 0x13bU)) ace.property[0] = 0;
        if (!(ace.flags & 2)) ace.inherited_class[0] = 0;
        visitor(ace);
    }
    return true;
}
#include "acl_hash.hpp"
static const char *ah_class_guid(const char *kind) {
    if (ah_eq(kind, "User")) return "bf967aba-0de6-11d0-a285-00aa003049e2";
    if (ah_eq(kind, "Computer")) return "bf967a86-0de6-11d0-a285-00aa003049e2";
    if (ah_eq(kind, "Group")) return "bf967a9c-0de6-11d0-a285-00aa003049e2";
    if (ah_eq(kind, "Domain")) return "19195a5a-6da0-11d0-afd3-00c04fd930c9";
    if (ah_eq(kind, "OU")) return "bf967aa5-0de6-11d0-a285-00aa003049e2";
    if (ah_eq(kind, "GPO")) return "f30e3bc2-9ff0-11d1-b603-0000f80367c1";
    if (ah_eq(kind, "Configuration")) return "bf967a87-0de6-11d0-a285-00aa003049e2";
    if (ah_eq(kind, "RootCA") || ah_eq(kind, "AIACA") || ah_eq(kind, "NTAuthStore")) return "3fdfee50-47f4-11d1-a9c3-0000f80367c1";
    if (ah_eq(kind, "EnterpriseCA")) return "ee4aa692-3bba-11d2-90cc-00c04fd91ab1";
    if (ah_eq(kind, "CertTemplate")) return "e5209ca2-3bba-11d2-90cc-00c04fd91ab1";
    if (ah_eq(kind, "IssuancePolicy")) return "37cfd85c-6719-4ad8-8f9e-8678ba627563";
    if (ah_eq(kind, "Site")) return "bf967ab3-0de6-11d0-a285-00aa003049e2";
    if (ah_eq(kind, "SiteServer")) return "bf967a92-0de6-11d0-a285-00aa003049e2";
    if (ah_eq(kind, "SiteSubnet")) return "b7b13124-b82e-11d0-afee-0000f80367c1";
    return "bf967a8b-0de6-11d0-a285-00aa003049e2";
}
static bool ah_ignore_sid(const char *sid) { return ah_eq(sid, "S-1-3-0") || ah_eq(sid, "S-1-5-18") || ah_eq(sid, "S-1-5-10"); }
static void ah_ad_acl(ah_graph &g, ah_buffer &b, ah_object *o, bool *owner_rights = nullptr, bool *inherited_owner_rights = nullptr) {
    if (owner_rights) *owner_rights = false;
    if (inherited_owner_rights) *inherited_owner_rights = false;
    if (ah_eq(o->kind, "SiteServer") || ah_eq(o->kind, "SiteSubnet")) { AH_TEXT(&b, "[]"); return; }
    AH_TEXT(&b, "["); bool first = true;
    auto emit = [&](const char *sid, const char *right, bool inherited, const ah_ace *source) {
        if (ah_ignore_sid(sid)) return;
        if (source && !ah_eq(right, "ReadGMSAPassword") && ah_eq(sid, "S-1-3-4")) {
            if (owner_rights) *owner_rights = true;
            if (inherited && inherited_owner_rights) *inherited_owner_rights = true;
        }
        if (!first) { AH_TEXT(&b, ","); } first = false;
        const char *hash = ah_eq(right, "ReadGMSAPassword") ? nullptr : source && inherited ? ah_inheritance_hash(g.arena, *source) : "";
        ah_principal(g, b, sid, true, right, inherited, hash, g.object_domain(o));
    };
    ah_value *sd = o->values("nTSecurityDescriptor");
    if (sd && sd->size >= 20) {
        const unsigned char *p = reinterpret_cast<unsigned char *>(sd->data); uint32_t owner = ah_u32(p + 4);
        char sid[192];
        if (owner) {
            if (owner >= sd->size || !ah_sid_string(sid, p + owner, sd->size - owner)) b.failed = true;
            else emit(sid, "Owns", false, nullptr);
        }
    }
    bool valid = ah_ad_rule_aces(sd, [&](const ah_ace &ace) {
        if (ace.type == 1 || ace.type == 6 || ah_ignore_sid(ace.sid)) return;
        bool inherited = (ace.flags & 0x10) != 0;
        if (!inherited && (ace.flags & 8)) return;
        const char *schema_kind = o->kind;
        if (inherited && *ace.inherited_class && !ah_eq(ace.inherited_class, "00000000-0000-0000-0000-000000000000") && !ah_eq(ace.inherited_class, ah_class_guid(schema_kind))) return;

        if(ah_builtin(ace.sid)) {
            const char *scope=ah_eq(ace.sid,"S-1-5-9")?g.forest_domain():g.object_domain(o);
            const char *qualified=ah_concat(g.arena,scope,"-",ace.sid);
            ah_object *principal=qualified?g.sids.find(qualified):nullptr;
            if(principal)ah_record_output_reference(g,qualified,true);
        }
        bool unrestricted = !*ace.property || ah_eq(ace.property, "00000000-0000-0000-0000-000000000000"), generic = unrestricted;
        uint32_t mask = ace.mask;
        if (generic && (mask & 0xf01ffU) == 0xf01ffU) { emit(ace.sid, "GenericAll", inherited, &ace); return; }
        bool generic_write = generic && (mask & 0x20028U) == 0x20028U;
        bool write_kind = !ah_eq(o->kind, "Container") && !ah_eq(o->kind, "Configuration");
        if (generic_write && write_kind) emit(ace.sid, "GenericWrite", inherited, &ace);
        if (generic) {
            if (mask & 0x40000U) emit(ace.sid, "WriteDacl", inherited, &ace);
            if (mask & 0x80000U) emit(ace.sid, "WriteOwner", inherited, &ace);
        }
        if (mask & 0x20U) {
            if (!generic_write && unrestricted && write_kind) emit(ace.sid, "GenericWrite", inherited, &ace);
            if (ah_eq(o->kind, "Group") && (ah_eq(ace.property, "bf9679c0-0de6-11d0-a285-00aa003049e2") || ah_eq(ace.property, "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"))) emit(ace.sid, "AddMember", inherited, &ace);
            if (ah_eq(o->kind, "Computer") && ah_eq(ace.property, "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")) emit(ace.sid, "AddAllowedToAct", inherited, &ace);
            if (ah_eq(o->kind, "Computer") && ah_eq(ace.property, "4c164200-20c0-11d0-a768-00aa006e0529")) emit(ace.sid, "WriteAccountRestrictions", inherited, &ace);
            if (ah_eq(o->kind, "User") && ah_eq(ace.property, "f3a64788-5306-11d1-a9c5-0000f80367c1")) emit(ace.sid, "WriteSPN", inherited, &ace);
            if ((ah_eq(o->kind, "User") || ah_eq(o->kind, "Computer")) && ah_eq(ace.property, "5b47d60f-6090-40b2-9f37-2a4de88f3063")) emit(ace.sid, "AddKeyCredentialLink", inherited, &ace);
            if ((ah_eq(o->kind, "User") || ah_eq(o->kind, "Computer")) && ah_eq(ace.property, "00fbf30c-91fe-11d1-aebc-0000f80367c1")) emit(ace.sid, "WriteAltSecurityIdentities", inherited, &ace);
            if ((ah_eq(o->kind, "User") || ah_eq(o->kind, "Computer")) && ah_eq(ace.property, "e48d0154-bcf8-11d1-8702-00c04fb96050")) emit(ace.sid, "WritePublicInformation", inherited, &ace);
            if ((ah_eq(o->kind, "Domain") || ah_eq(o->kind, "OU") || ah_eq(o->kind, "Site")) && ah_eq(ace.property, "f30e3bbe-9ff0-11d1-b603-0000f80367c1")) emit(ace.sid, "WriteGPLink", inherited, &ace);
            if (ah_eq(o->kind, "CertTemplate") && ah_eq(ace.property, "d15ef7d8-f226-46db-ae79-b34e560bd12c")) emit(ace.sid, "WritePKIEnrollmentFlag", inherited, &ace);
            if (ah_eq(o->kind, "CertTemplate") && ah_eq(ace.property, "ea1dddc4-60ff-416e-8cc0-17cee534bce7")) emit(ace.sid, "WritePKINameFlag", inherited, &ace);
        }
        if ((mask & 8U) && !(mask & 0x20U) && !generic_write && ah_eq(o->kind, "Group") && (unrestricted || ah_eq(ace.property, "bf9679c0-0de6-11d0-a285-00aa003049e2") || ah_eq(ace.property, "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"))) emit(ace.sid, "AddSelf", inherited, &ace);
        if (mask & 0x100U) {
            if (ah_eq(o->kind, "Domain")) {
                if (ah_eq(ace.property, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")) emit(ace.sid, "GetChanges", inherited, &ace);
                else if (ah_eq(ace.property, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")) emit(ace.sid, "GetChangesAll", inherited, &ace);
                else if (ah_eq(ace.property, "89e95b76-444d-4c62-991a-0facbeda640c")) emit(ace.sid, "GetChangesInFilteredSet", inherited, &ace);
                else if (unrestricted) emit(ace.sid, "AllExtendedRights", inherited, &ace);
            } else if (ah_eq(o->kind, "User")) {
                if (ah_eq(ace.property, "00299570-246d-11d0-a768-00aa006e0529")) emit(ace.sid, "ForceChangePassword", inherited, &ace);
                else if (unrestricted) emit(ace.sid, "AllExtendedRights", inherited, &ace);
            } else if (ah_eq(o->kind, "Computer") && unrestricted && (ah_integer(o, "ms-Mcs-AdmPwdExpirationTime") > 0 || ah_integer(o, "msLAPS-PasswordExpirationTime") > 0)) emit(ace.sid, "AllExtendedRights", inherited, &ace);
            if (ah_eq(o->kind, "CertTemplate")) {
                if (unrestricted) emit(ace.sid, "AllExtendedRights", inherited, &ace);
                else if (ah_eq(ace.property, "0e10c968-78fb-11d2-90d4-00c04f79dc55")) emit(ace.sid, "Enroll", inherited, &ace);
            }
        }
        if (ah_eq(o->kind, "EnterpriseCA")) {
            if (mask & 1U) emit(ace.sid, "ManageCA", inherited, &ace);
            if (mask & 2U) emit(ace.sid, "ManageCertificates", inherited, &ace);
            if (ah_eq(ace.property, "0e10c968-78fb-11d2-90d4-00c04f79dc55")) emit(ace.sid, "Enroll", inherited, &ace);
            if (mask & 0x200U) emit(ace.sid, "Enroll", inherited, &ace);
        }
        bool laps_object = ah_integer(o, "ms-Mcs-AdmPwdExpirationTime") > 0 || ah_integer(o, "msLAPS-PasswordExpirationTime") > 0;
        bool laps_right = (g.laps_guid && ah_eq(ace.property, g.laps_guid)) || (g.laps_guid_v2 && ah_eq(ace.property, g.laps_guid_v2)) || (g.laps_guid_v3 && ah_eq(ace.property, g.laps_guid_v3));
        if (ah_eq(o->kind, "Computer") && laps_object && (mask & 0x100U) && laps_right) emit(ace.sid, "ReadLAPSPassword", inherited, &ace);
    });
    if (ah_eq(o->kind, "User") && o->values("msDS-GroupMSAMembership")) {
        bool gmsa_valid = ah_ad_rule_aces(o->values("msDS-GroupMSAMembership"), [&](const ah_ace &ace) {
            if (ace.type != 1 && ace.type != 6 && !ah_ignore_sid(ace.sid) && ah_resolved_sid_kind(g, ace.sid)) emit(ace.sid, "ReadGMSAPassword", (ace.flags & 0x10) != 0, &ace);
        });
        if (!gmsa_valid) valid = false;
    }
    if (!valid) b.failed = true;
    AH_TEXT(&b, "]");
}
static bool ah_owner_rights(ah_graph &g, ah_object *o, bool inherited) {

    if (!ah_raw_owner_rights(o, false) && !ah_raw_owner_rights(o, true)) return false;
    ah_buffer edges(16 * 1024 * 1024); bool any = false, any_inherited = false;
    ah_ad_acl(g, edges, o, &any, &any_inherited);
    return !edges.failed && (inherited ? any_inherited : any);
}
static void ah_ad_trusts(ah_graph &g, ah_buffer &b) {
    AH_TEXT(&b, "["); bool first = true;
    if (!(ah_collection & AH_TRUSTS)) { AH_TEXT(&b, "]"); return; }
    PDS_DOMAIN_TRUSTSW native = nullptr; ULONG total = 0, primary = 0xffffffffU;
    if (NETAPI32$DsEnumerateDomainTrustsW(const_cast<wchar_t *>(ah_current_dc), DS_DOMAIN_IN_FOREST | DS_DOMAIN_DIRECT_INBOUND | DS_DOMAIN_DIRECT_OUTBOUND, &native, &total) == ERROR_SUCCESS) {
        for (ULONG i = 0; i < total; ++i) if (native[i].Flags & DS_DOMAIN_PRIMARY) { primary = i; break; }
    }
    for (ah_object *o = g.directory.objects; o; o = o->next) if (ah_weq(o->type, L"trusts")) {
        ah_value *value = o->values("securityIdentifier"); char sid[192] = {};
        if (!value || !o->values("trustDirection") || !o->values("trustAttributes") || !ah_sid_string(sid, reinterpret_cast<unsigned char *>(value->data), value->size)) continue;
        uint64_t flags = ah_unsigned(o->text("trustAttributes")), direction = ah_unsigned(o->text("trustDirection"));
        const char *target = o->text("trustPartner", o->text("cn", o->text("name")));
        const char *kind = flags & 0x20 ? "ParentChild" : flags & 8 ? "Forest" : "External";
        for (ULONG i = 0; i < total && native; ++i) {
            if (!native[i].DnsDomainName) continue;
            char *dns = g.arena.utf8(native[i].DnsDomainName);
            if (!ah_eq(dns, target)) continue;
            if ((native[i].Flags & DS_DOMAIN_IN_FOREST) && primary < total) {
                bool parent = !(native[primary].Flags & DS_DOMAIN_TREE_ROOT) && native[primary].ParentIndex == i;
                bool child = !(native[i].Flags & DS_DOMAIN_TREE_ROOT) && native[i].ParentIndex == primary;
                kind = parent || child ? "ParentChild" : (native[i].Flags & DS_DOMAIN_TREE_ROOT) && (native[primary].Flags & DS_DOMAIN_TREE_ROOT) ? "TreeRoot" : "CrossLink";
            } else if (native[i].TrustType == 3) kind = "Kerberos";
            break;
        }
        if (!first) { AH_TEXT(&b, ","); } first = false;
        AH_TEXT(&b, "{"); ah_fields fields(b);
        fields.text("TargetDomainName", ah_upper(g.arena, target)); fields.text("TargetDomainSid", sid);
        fields.text("TrustDirection", direction == 1 ? "Inbound" : direction == 2 ? "Outbound" : direction == 3 ? "Bidirectional" : "Disabled");
        fields.text("TrustType", kind); fields.number("TrustAttributes", flags);
        fields.boolean("IsTransitive", !(flags & 1));
        fields.boolean("SidFilteringEnabled", (flags & 4) || ((flags & 8) && !(flags & 0x40)));
        fields.boolean("TGTDelegationEnabled", !(flags & 4) && (flags & (0x20 | 0x800)));
        AH_TEXT(&b, "}");
    }
    if (native) NETAPI32$NetApiBufferFree(native);
    AH_TEXT(&b, "]");
}

struct ah_token_principal { const char *sid, *name, *kind; };
static const ah_token_principal ah_token_principals[] = {
        {"S-1-0", "Null Authority", "User"},
        {"S-1-0-0", "Nobody", "User"},
        {"S-1-1", "World Authority", "User"},
        {"S-1-1-0", "Everyone", "Group"},
        {"S-1-2", "Local Authority", "User"},
        {"S-1-2-0", "Local", "Group"},
        {"S-1-2-1", "Console Logon", "Group"},
        {"S-1-3", "Creator Authority", "User"},
        {"S-1-3-0", "Creator Owner", "User"},
        {"S-1-3-1", "Creator Group", "Group"},
        {"S-1-3-2", "Creator Owner Server", "Computer"},
        {"S-1-3-3", "Creator Group Server", "Computer"},
        {"S-1-3-4", "Owner Rights", "Group"},
        {"S-1-4", "Non-unique Authority", "User"},
        {"S-1-5", "NT Authority", "User"},
        {"S-1-5-1", "Dialup", "Group"},
        {"S-1-5-2", "Network", "Group"},
        {"S-1-5-3", "Batch", "Group"},
        {"S-1-5-4", "Interactive", "Group"},
        {"S-1-5-6", "Service", "Group"},
        {"S-1-5-7", "Anonymous", "Group"},
        {"S-1-5-8", "Proxy", "Group"},
        {"S-1-5-9", "Enterprise Domain Controllers", "Group"},
        {"S-1-5-10", "Principal Self", "User"},
        {"S-1-5-11", "Authenticated Users", "Group"},
        {"S-1-5-12", "Restricted Code", "Group"},
        {"S-1-5-13", "Terminal Server Users", "Group"},
        {"S-1-5-14", "Remote Interactive Logon", "Group"},
        {"S-1-5-15", "This Organization", "Group"},
        {"S-1-5-17", "IUSR", "User"},
        {"S-1-5-18", "Local System", "User"},
        {"S-1-5-19", "Local Service", "User"},
        {"S-1-5-20", "Network Service", "User"},
        {"S-1-5-21-0-0-0-496", "Compounded Authentication", "Group"},
        {"S-1-5-21-0-0-0-497", "Claims Valid", "Group"},
        {"S-1-5-32-544", "Administrators", "Group"},
        {"S-1-5-32-545", "Users", "Group"},
        {"S-1-5-32-546", "Guests", "Group"},
        {"S-1-5-32-547", "Power Users", "Group"},
        {"S-1-5-32-548", "Account Operators", "Group"},
        {"S-1-5-32-549", "Server Operators", "Group"},
        {"S-1-5-32-550", "Print Operators", "Group"},
        {"S-1-5-32-551", "Backup Operators", "Group"},
        {"S-1-5-32-552", "Replicators", "Group"},
        {"S-1-5-32-554", "Pre-Windows 2000 Compatible Access", "Group"},
        {"S-1-5-32-555", "Remote Desktop Users", "Group"},
        {"S-1-5-32-556", "Network Configuration Operators", "Group"},
        {"S-1-5-32-557", "Incoming Forest Trust Builders", "Group"},
        {"S-1-5-32-558", "Performance Monitor Users", "Group"},
        {"S-1-5-32-559", "Performance Log Users", "Group"},
        {"S-1-5-32-560", "Windows Authorization Access Group", "Group"},
        {"S-1-5-32-561", "Terminal Server License Servers", "Group"},
        {"S-1-5-32-562", "Distributed COM Users", "Group"},
        {"S-1-5-32-568", "IIS_IUSRS", "Group"},
        {"S-1-5-32-569", "Cryptographic Operators", "Group"},
        {"S-1-5-32-573", "Event Log Readers", "Group"},
        {"S-1-5-32-574", "Certificate Service DCOM Access", "Group"},
        {"S-1-5-32-575", "RDS Remote Access Servers", "Group"},
        {"S-1-5-32-576", "RDS Endpoint Servers", "Group"},
        {"S-1-5-32-577", "RDS Management Servers", "Group"},
        {"S-1-5-32-578", "Hyper-V Administrators", "Group"},
        {"S-1-5-32-579", "Access Control Assistance Operators", "Group"},
        {"S-1-5-32-580", "Remote Management Users", "Group"},
        {"S-1-5-32-581", "System Managed Accounts Group", "Group"},
        {"S-1-5-32-582", "Storage Replica Administrators", "Group"},
        {"S-1-5-32-583", "Device Owners", "Group"},
        {"S-1-5-64-10", "NTLM Authentication", "Group"},
        {"S-1-5-64-14", "Schannel Authentication", "Group"},
        {"S-1-5-64-21", "Digest Authentication", "Group"},
        {"S-1-5-65-1", "This Organization Certificate", "Group"},
        {"S-1-5-80", "Service", "Group"},
        {"S-1-5-80-0", "All Services ", "Group"},
        {"S-1-5-82", "IIS AppPool", "Group"},
        {"S-1-5-90", "Window Manager\\Window Manager Group", "Group"},
        {"S-1-5-96", "Font Driver Host\\UMFD-0", "Computer"},
        {"S-1-5-113", "Local Account", "User"},
        {"S-1-5-114", "Local Account and Member of Administrators Group", "User"},
        {"S-1-5-1000", "Other Organization", "Group"},
        {"S-1-18-1", "Authentication Authority Asserted Identity", "Group"},
        {"S-1-18-2", "Service Asserted Identity", "Group"},
        {"S-1-18-3", "Fresh Public Key Identity", "Group"},
        {"S-1-18-4", "Key Trust", "Group"},
        {"S-1-18-5", "MFA Key Property", "Group"},
        {"S-1-18-6", "Attested Key Property", "Group"}
    };
static const char *ah_wellknown_name(const char *sid) {
    for(const auto &principal:ah_token_principals)if(ah_eq(principal.sid,sid))return principal.name;
    return nullptr;
}
static bool ah_ad_wellknown(ah_directory &data) {
    constexpr size_t principal_count=sizeof(ah_token_principals)/sizeof(ah_token_principals[0]);
    bool found[principal_count]={};

    for (ah_object *o=data.objects;o&&!data.arena.failed;o=o->next) {
        ah_value *value=o->values("objectSid");char existing[192];
        if(!value||!ah_sid_string(existing,reinterpret_cast<unsigned char*>(value->data),value->size))continue;
        if(ah_prefix(existing,"S-1-5-21-")&&!ah_prefix(existing,"S-1-5-21-0-0-0-"))continue;
        if(*o->text("__adaptihoundOwnerDomain")||ah_weq(o->type,L"foreignsecurityprincipals"))continue;
        for(size_t i=0;i<principal_count;++i)if(!found[i]&&ah_eq(existing,ah_token_principals[i].sid)) {
            if(*o->dn)data.value(data.attribute(o,"__adaptihoundWellKnownName"),ah_token_principals[i].name,ah_len(ah_token_principals[i].name));
            found[i]=true;break;
        }
    }
    for (size_t i=0;i<principal_count;++i) {
        const ah_token_principal &principal=ah_token_principals[i];
        if(found[i])continue;
        unsigned char binary[68];size_t sid_size=0;
        if(!ah_gpo_sid_bytes(principal.sid,binary,sid_size))return false;
        const wchar_t *type = ah_eq(principal.kind, "User") ? L"users" : ah_eq(principal.kind, "Computer") ? L"computers" : L"groups";
        ah_object *o = data.add(type, "");
        if (!o) return false;
        data.value(data.attribute(o, "objectSid"), reinterpret_cast<char *>(binary), sid_size);
        data.value(data.attribute(o, "sAMAccountName"), principal.name, ah_len(principal.name));
    }
    return !data.arena.failed;
}

static const char *ah_level(uint64_t n) {
    switch (n) { case 0: return "2000 Mixed/Native"; case 1: return "2003 Interim"; case 2: return "2003"; case 3: return "2008"; case 4: return "2008 R2"; case 5: return "2012"; case 6: return "2012 R2"; case 7: return "2016"; case 8: return "2025"; default: return "Unknown"; }
}
static void ah_ad_encryption_types(ah_buffer &b, const ah_object *o) {
    if (!o->values("msDS-SupportedEncryptionTypes")) { AH_TEXT(&b, "null"); return; }
    uint32_t mask = static_cast<uint32_t>(ah_unsigned(o->text("msDS-SupportedEncryptionTypes")));
    AH_TEXT(&b, "["); bool first = true;
    auto emit = [&](const char *name) { if (!first) { AH_TEXT(&b, ","); } first = false; ah_string(b, name); };
    if (!mask) emit("Not defined");
    if (mask & 1) emit("DES-CBC-CRC");
    if (mask & 2) emit("DES-CBC-MD5");
    if (mask & 4) emit("RC4-HMAC-MD5");
    if (mask & 8) emit("AES128-CTS-HMAC-SHA1-96");
    if (mask & 16) emit("AES256-CTS-HMAC-SHA1-96");
    AH_TEXT(&b, "]");
}

static void ah_spn_targets(ah_graph &g, ah_buffer &b, ah_object *o) {
    if (!(ah_collection & AH_SPN_TARGETS)) { AH_TEXT(&b, "[]"); return; }
    AH_TEXT(&b, "["); bool first = true;
    for (ah_value *v = o->values("servicePrincipalName"); v; v = v->next) {
        const char *spn = v->data;
        size_t spn_length = ah_len(spn);
        if (spn_length < 9) continue;
        bool sql = false;
        for (size_t i = 0; i + 8 <= spn_length; ++i) if (ah_lower(spn[i]) == 'm' && ah_lower(spn[i + 1]) == 's' && ah_lower(spn[i + 2]) == 's' && ah_lower(spn[i + 3]) == 'q' && ah_lower(spn[i + 4]) == 'l' && ah_lower(spn[i + 5]) == 's' && ah_lower(spn[i + 6]) == 'v' && ah_lower(spn[i + 7]) == 'c') { sql = true; break; }
        if (!sql) continue;
        bool upn = false; for (const char *c = spn; *c; ++c) if (*c == '@') upn = true;
        if (upn) continue;
        const char *host = spn;
        while (*host && *host != '/') ++host;
        if (!*host) continue;
        ++host;
        const char *end = host;
        while (*end && *end != ':' && *end != '/') ++end;
        const char *computer_sid = ah_session_lookup_host(g, g.arena.copy(host, static_cast<size_t>(end - host)));
        if (!computer_sid || !ah_prefix(computer_sid, "S-1")) continue;
        if (ah_track_computer_calls && ah_prefix(computer_sid, "S-1")) {
            size_t length = static_cast<size_t>(end - host); while (length && host[length - 1] == '$') --length;
            ah_track_resolved_call(g, ah_upper(g.arena, g.arena.copy(host, length)), computer_sid, "ReadSPNTargets", "Success");
        }

        int32_t port = 1433;
        const char *colon = spn; while (*colon && *colon != ':') ++colon;
        if (*colon) {
            const char *last = ++colon; while (*last && *last != ':') ++last;
            int64_t parsed = 0;
            if (ah_try_int64_text(g.arena.copy(colon, static_cast<size_t>(last - colon)), parsed) && parsed >= INT32_MIN && parsed <= INT32_MAX)
                port = static_cast<int32_t>(parsed);
        }
        if (!first) { AH_TEXT(&b, ","); }
        first = false; AH_TEXT(&b, "{\"ComputerSID\":"); ah_string(b, computer_sid);
        AH_TEXT(&b, ",\"Port\":"); ah_int64(b, port); AH_TEXT(&b, ",\"Service\":\"SQLAdmin\"}");
    }
    AH_TEXT(&b, "]");
}

static void ah_registry_int_result(ah_buffer &b, bool requested, bool collected, bool present, uint32_t value, const char *reason) {
    if (!requested) { AH_TEXT(&b, "null"); return; }
    AH_TEXT(&b, "{\"Value\":");
    ah_int64(b, collected ? (present ? static_cast<int32_t>(value) : -1) : 0);
    AH_TEXT(&b, ",\"Collected\":"); if (collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"FailureReason\":"); if (collected) AH_TEXT(&b, "null"); else ah_string(b, reason ? reason : "RegistryQueryFailed");
    AH_TEXT(&b, "}");
}
static void ah_registry_string_result(ah_buffer &b, bool requested, bool collected, const char *value, const char *reason) {
    if (!requested) { AH_TEXT(&b, "null"); return; }
    AH_TEXT(&b, "{\"Value\":"); if (collected && value) ah_string(b, value); else AH_TEXT(&b, "null");
    AH_TEXT(&b, ",\"Collected\":"); if (collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"FailureReason\":"); if (collected) AH_TEXT(&b, "null"); else ah_string(b, reason ? reason : "RegistryQueryFailed");
    AH_TEXT(&b, "}");
}

static void ah_nullable_dword(ah_buffer &b, bool present, uint32_t value) {
    if (!present) { AH_TEXT(&b, "null"); return; }
    char digits[32]; const char *number = ah_decimal(digits + sizeof(digits), value);
    ah_append(&b, number, ah_len(number));
}

static void ah_ntlm_registry_result(ah_buffer &b, const ah_object *o) {
    if (!o->ntlm_registry_requested) { AH_TEXT(&b, "null"); return; }
    if (!o->ntlm_registry_collected) {
        AH_TEXT(&b, "{\"Result\":null,\"Collected\":false,\"FailureReason\":");
        ah_string(b, o->ntlm_registry_failure ? o->ntlm_registry_failure : "RegistryQueryFailed"); AH_TEXT(&b, "}"); return;
    }
    AH_TEXT(&b, "{\"Result\":{\"RestrictSendingNtlmTraffic\":"); ah_nullable_dword(b, o->restrict_sending_valid, o->restrict_sending);
    AH_TEXT(&b, ",\"RestrictReceivingNtlmTraffic\":"); ah_nullable_dword(b, o->restrict_receiving_valid, o->restrict_receiving);
    AH_TEXT(&b, ",\"NtlmMinServerSec\":"); ah_nullable_dword(b, o->min_server_valid, o->min_server);
    AH_TEXT(&b, ",\"NtlmMinClientSec\":"); ah_nullable_dword(b, o->min_client_valid, o->min_client);
    AH_TEXT(&b, ",\"LmCompatibilityLevel\":"); ah_nullable_dword(b, o->lm_level_valid, o->lm_level);
    AH_TEXT(&b, ",\"UseMachineId\":"); ah_nullable_dword(b, o->use_machine_id_valid, o->use_machine_id);
    AH_TEXT(&b, ",\"RequireSecuritySignature\":"); ah_nullable_dword(b, o->ntlm_require_signing_valid, o->ntlm_require_signing);
    AH_TEXT(&b, ",\"EnableSecuritySignature\":"); ah_nullable_dword(b, o->enable_signing_valid, o->enable_signing);
    AH_TEXT(&b, ",\"ClientAllowedNTLMServers\":"); if (o->client_allowed_servers_valid) ah_text_array(b, o->client_allowed_servers); else AH_TEXT(&b, "null");
    AH_TEXT(&b, "},\"Collected\":true,\"FailureReason\":null}");
}

static void ah_sid_history(ah_graph &g, ah_buffer &b, ah_object *o, bool references) {
    AH_TEXT(&b, "["); bool first = true;
    struct seen_sid { char sid[192]; seen_sid *next; }; seen_sid *seen = nullptr;
    for (ah_value *v = o->values("sIDHistory"); v; v = v->next) {
        char sid[192]; if (!ah_sid_string(sid, reinterpret_cast<unsigned char *>(v->data), v->size)) continue;
        if (references) {
            if (!ah_resolved_sid_kind(g, sid)) continue;
            bool duplicate = false; for (seen_sid *p = seen; p; p = p->next) if (ah_eq(p->sid, sid)) duplicate = true;
            if (duplicate) continue;
            seen_sid *entry = g.arena.make<seen_sid>(); if (!entry) return;
            size_t n = ah_len(sid); for (size_t i = 0; i <= n; ++i) entry->sid[i] = sid[i]; entry->next = seen; seen = entry;
        }
        if (!first) { AH_TEXT(&b, ","); } first = false;
        if (references) ah_principal(g, b, sid, false); else ah_string(b, sid);
    }
    AH_TEXT(&b, "]");
}
static void ah_nullable_property(ah_fields &props, ah_buffer &b, const ah_object *o, const char *name, const char *attribute) {
    props.key(name); ah_value *v = o->values(attribute);
    if (v) ah_json_bytes(&b, v->data, v->size); else AH_TEXT(&b, "null");
}
static void ah_bool_api_result(ah_buffer &b, bool collected, bool value, const char *reason) {
    AH_TEXT(&b, "{\"Result\":"); if (value) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"Collected\":"); if (collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"FailureReason\":"); if (collected) AH_TEXT(&b, "null"); else { if (reason) ah_string(b, reason); else AH_TEXT(&b, "null"); }
    AH_TEXT(&b, "}");
}

static void ah_ad_node(ah_graph &g, ah_buffer &b, ah_object *o) {
    const bool user = ah_eq(o->kind, "User"), computer = ah_eq(o->kind, "Computer"), group = ah_eq(o->kind, "Group"), domain = ah_eq(o->kind, "Domain"), ou = ah_eq(o->kind, "OU"), container = ah_eq(o->kind, "Container") || ah_eq(o->kind, "Configuration") || (ah_weq(o->type, L"issuancepolicies") && ah_prefix(o->dn, "CN=OID,CN=Public Key Services")), gpo = ah_eq(o->kind, "GPO");
    const char *object_domain = g.object_domain(o), *object_domain_sid = g.object_domain_sid(o);
    int64_t parsed_uac=0; const bool uac_present=ah_try_property_long(o,"userAccountControl",parsed_uac);
    uint64_t uac=static_cast<uint64_t>(parsed_uac);
    ah_value *sd = o->values("nTSecurityDescriptor");
    AH_TEXT(&b, "{"); ah_fields node(b);
    node.text("ObjectIdentifier", o->id);
    node.key("Properties"); AH_TEXT(&b, "{"); ah_fields props(b);
    const char *account = o->text("sAMAccountName", nullptr);
    const bool wellknown = !*o->dn && ah_builtin(o->raw_sid);
    const bool collect_props = (ah_collection & AH_OBJECT_PROPS) && !wellknown;
    const bool collect_acl = (ah_collection & (AH_ACL | (container ? AH_CERT_SERVICES : 0))) && !wellknown;
    const bool collect_container = (ah_collection & (AH_CONTAINER | (container ? AH_CERT_SERVICES : 0))) && !wellknown;
    const char *display = nullptr;
    if (domain) display = object_domain;
    else if (o->raw_sid && ah_builtin(o->raw_sid)) display=ah_concat(g.arena,o->text("__adaptihoundWellKnownName",account?account:"UNKNOWN"),"@",object_domain);
    else if (computer && !wellknown) {
        const char *dns = o->text("dNSHostName", nullptr);
        if (dns) display = dns;
        else {
            const char *short_name = account && *account ? account : o->text("cn", o->text("name", "UNKNOWN"));
            size_t n = ah_len(short_name); while (n && short_name[n - 1] == '$') --n;
            display = ah_concat(g.arena, g.arena.copy(short_name, n), ".", object_domain);
        }
    } else {
        const char *name = (user || group || wellknown) && account && *account ? account : gpo ? o->text("displayName", o->text("cn", "UNKNOWN")) : o->text("name", o->text("cn", "UNKNOWN"));
        display = ah_concat(g.arena, name, "@", object_domain);
    }
    props.text("name", ah_upper(g.arena, display));
    props.text("domain", object_domain);
    if (object_domain_sid && *object_domain_sid) props.text("domainsid", object_domain_sid);
    if (*o->dn) props.text("distinguishedname", ah_upper(g.arena, o->dn));
    if (wellknown && !ah_eq(o->raw_sid, "S-1-5-9")) props.boolean("reconcile", false);
    if ((user || group || computer) && !wellknown) props.nullable_text("samaccountname", account);
    if (user && ah_has(o, "objectClass", "msDS-ManagedServiceAccount")) props.boolean("msa", true);
    if (user && ah_has(o, "objectClass", "msDS-GroupManagedServiceAccount")) props.boolean("gmsa", true);
    if (computer && !wellknown) props.boolean("haslaps", ah_has_laps(o));
    if (collect_acl) {
        props.boolean("doesanyacegrantownerrights", ah_owner_rights(g, o, false)); props.boolean("doesanyinheritedacegrantownerrights", ah_owner_rights(g, o, true));
        props.boolean("isaclprotected", sd && sd->size >= 20 && (ah_u16(reinterpret_cast<unsigned char *>(sd->data) + 2) & 0x1000));
        if (user || computer || group) {
            int protected_by_holder = ah_admin_sdholder_protected(g, o);
            if (protected_by_holder >= 0) props.boolean("adminsdholderprotected", protected_by_holder == 1);
        }
    }
    if (collect_props || (container && (ah_collection & AH_CERT_SERVICES))) ah_common_object_properties(g, b, props, o);
    if (collect_props && (user || computer)) {
        const bool user_uac = user && uac_present;
        if (computer || user_uac) {
            props.boolean("enabled", !(uac & 2)); props.boolean("unconstraineddelegation", (uac & 0x80000) != 0);
            props.boolean("trustedtoauth", (uac & 0x1000000) != 0);
            props.number("useraccountcontrol", uac); props.boolean("encryptedtextpwdallowed", (uac & 0x80) != 0);
            props.boolean("usedeskeyonly", (uac & 0x200000) != 0); props.boolean("passwordexpired", (uac & 0x800000) != 0);
            props.boolean("lockedout", (uac & 0x10) != 0); props.boolean("logonscriptenabled", (uac & 1) != 0);
        }
        if (user_uac) {
            props.boolean("sensitive", (uac & 0x100000) != 0); props.boolean("dontreqpreauth", (uac & 0x400000) != 0);
            props.boolean("pwdneverexpires", (uac & 0x10000) != 0); props.boolean("passwordnotreqd", (uac & 0x20) != 0);
            props.boolean("passwordcantchange", (uac & 0x40) != 0); props.boolean("smartcardrequired", (uac & 0x40000) != 0);
        }
        const char *aad = ah_trim_text(g.arena, o->text("msDS-AADObjectID", nullptr));
        if (user && aad && *aad) props.text("aadobjectid", ah_upper(g.arena, aad));
        props.boolean("admincount", ah_integer(o, "adminCount") != 0);
        props.key("supportedencryptiontypes"); ah_ad_encryption_types(b, o);
        props.key("serviceprincipalnames"); ah_text_array(b, o->values("servicePrincipalName"));
        if (user) props.boolean("hasspn", o->values("servicePrincipalName") != nullptr);
        if (o->values("msDS-AllowedToDelegateTo") && (computer || user_uac)) { props.key("allowedtodelegate"); ah_text_array(b, o->values("msDS-AllowedToDelegateTo")); }
        props.number("pwdlastset", ah_time(o, "pwdLastSet")); props.number("lastlogon", ah_time(o, "lastLogon")); props.number("lastlogontimestamp", ah_time(o, "lastLogonTimestamp"));
        props.key("sidhistory"); ah_sid_history(g, b, o, false);
        props.nullable_text("email", o->text("mail", nullptr));
    }
    if (collect_props && user) {
        props.nullable_text("displayname", o->text("displayName", nullptr)); props.nullable_text("title", o->text("title", nullptr));
        props.nullable_text("homedirectory", o->text("homeDirectory", nullptr)); props.nullable_text("logonscript", o->text("scriptPath", nullptr)); props.nullable_text("profilepath", o->text("profilePath", nullptr));
        ah_nullable_property(props, b, o, "userpassword", "userPassword"); ah_nullable_property(props, b, o, "unixpassword", "unixUserPassword");
        ah_nullable_property(props, b, o, "unicodepassword", "unicodePwd"); ah_nullable_property(props, b, o, "sfupassword", "msSFU30Password");
    }
    if (collect_props && computer) {
        const char *os = o->text("operatingSystem", nullptr), *sp = o->text("operatingSystemServicePack", nullptr);
        props.nullable_text("operatingsystem", sp ? ah_concat(g.arena, os ? os : "", " ", sp) : os);
        props.boolean("isdc", (uac & 0x2000) != 0); props.boolean("isreadonlydc", (uac & 0x4000000) != 0);
    }
    if (computer && o->azure_registry_collected) props.nullable_text("azvmid", o->azure_vm_id);
    if (computer && !wellknown && (ah_collection & AH_LDAP_SERVICES) && (uac & 0x2000) && o->host_connectable) {
        props.boolean("ldapavailable",o->ldap_available);props.boolean("ldapsavailable",o->ldaps_available);
        if(o->ldaps_cbt_valid)props.boolean("ldapsepa",!o->ldaps_cbt_disabled);
        if(o->ldap_signing_valid)props.boolean("ldapsigning",o->ldap_signing);
    }
    if (collect_props && group) {
        props.key("sidhistory"); ah_sid_history(g, b, o, false);
        props.boolean("admincount", ah_integer(o, "adminCount") != 0);
        const char *aad = ah_trim_text(g.arena, o->text("msDS-AADObjectID", nullptr)); if (aad && *aad) props.text("aadobjectid", ah_upper(g.arena, aad));
        int64_t group_type = ah_integer(o, "groupType"); props.text("groupscope", (group_type & 8) ? "Universal" : (group_type & 4) ? "DomainLocal" : (group_type & 2) ? "Global" : "Unknown");
    }

    if (domain && !o->auxiliary_only && !ah_stealth) props.boolean("collected",true);
    if (collect_props && domain) {
        if (o->values("msDS-ExpirePasswordsOnSmartCardOnlyAccounts")) props.boolean("expirepasswordsonsmartcardonlyaccounts", ah_eq(o->text("msDS-ExpirePasswordsOnSmartCardOnlyAccounts"), "TRUE"));
        const char *principal_name = o->text("msDS-PrincipalName"), *separator = principal_name;
        while (*separator && *separator != '\\') ++separator;
        if (*separator && separator != principal_name) props.text("netbios", g.arena.copy(principal_name, static_cast<size_t>(separator - principal_name)));
        int64_t functional_level=-1; if(!ah_try_property_long(o,"msDS-Behavior-Version",functional_level))functional_level=-1;
        props.text("functionallevel", ah_level(static_cast<uint64_t>(functional_level)));
        const char *heuristics = nullptr;
        for (ah_object *aux = g.directory.objects; aux; aux = aux->next) if (ah_weq(aux->type, L"directoryservices")) heuristics = aux->text("dsHeuristics", nullptr);
        props.nullable_text("dsheuristics", heuristics);
        const char *numbers[] = {"machineaccountquota","minpwdlength","pwdproperties","pwdhistorylength","lockoutthreshold"};
        const char *attributes[] = {"ms-DS-MachineAccountQuota","minPwdLength","pwdProperties","pwdHistoryLength","lockoutThreshold"};
        for (unsigned int i = 0; i < 5; ++i) if (o->values(attributes[i])) props.number(numbers[i], ah_integer(o, attributes[i]));
        const char *durations[] = {"minpwdage","maxpwdage","lockoutduration"}; const char *duration_attrs[] = {"minPwdAge","maxPwdAge","lockoutDuration"};
        for (unsigned int i = 0; i < 3; ++i) if (o->values(duration_attrs[i]) && ah_integer(o, duration_attrs[i]) <= 0) {
            const char *value = ah_domain_duration(g.arena, o, duration_attrs[i]); if (value) props.text(durations[i], value);
        }
        if (o->values("lockoutObservationWindow") && ah_integer(o, "lockoutObservationWindow") <= 0) props.number("lockoutobservationwindow", ah_integer(o, "lockoutObservationWindow"));
    }
    if (ou && collect_container) props.boolean("blocksinheritance", ah_eq(o->text("gPOptions"), "1"));
    if (gpo && collect_props) { props.text("gpcpath", ah_upper(g.arena, o->text("gPCFileSysPath"))); props.text("gpostatus", o->text("flags")); }
    if (collect_props) ah_extra_properties(g, b, props, o);
    AH_TEXT(&b, "}");
    node.key("Aces"); if (collect_acl) ah_ad_acl(g, b, o); else AH_TEXT(&b, "[]");
    node.boolean("IsACLProtected", collect_acl && sd && sd->size >= 20 && (ah_u16(reinterpret_cast<unsigned char *>(sd->data) + 2) & 0x1000));
    node.boolean("IsDeleted", false); node.key("ContainedBy"); if (collect_container && !domain && !gpo) ah_directory_ref(g, b, ah_parent(o->dn)); else AH_TEXT(&b, "null");
    if (user || computer) {
        node.key("PrimaryGroupSID");
        if ((ah_collection & AH_GROUP) && !wellknown && *o->text("primaryGroupID") && o->raw_sid) {
            const char *last = o->raw_sid;
            for (const char *p = o->raw_sid; *p; ++p) if (*p == '-') last = p;
            ah_string(b, ah_concat(g.arena, g.arena.copy(o->raw_sid, static_cast<size_t>(last - o->raw_sid)), "-", o->text("primaryGroupID")));
        } else AH_TEXT(&b, "null");
        node.key("AllowedToDelegate"); AH_TEXT(&b, "["); bool first = true;
        struct delegated_sid { const char *sid; delegated_sid *next; }; delegated_sid *seen = nullptr;
        for (ah_value *v = collect_props && (computer || uac_present) ? o->values("msDS-AllowedToDelegateTo") : nullptr; v; v = v->next) {
            const char *host = v->data; while (*host && *host != '/') ++host; if (*host) ++host;
            const char *end = host; while (*end && *end != ':' && *end != '/') ++end;
            const char *sid = ah_session_lookup_host(g, g.arena.copy(host, static_cast<size_t>(end - host)));
            if (!sid) continue;
            bool duplicate = false; for (delegated_sid *p = seen; p; p = p->next) if (ah_eq(p->sid, sid)) duplicate = true;
            if (duplicate) continue;
            delegated_sid *entry = g.arena.make<delegated_sid>(); if (!entry) break;
            entry->sid = sid; entry->next = seen; seen = entry;
            if (ah_track_computer_calls && ah_prefix(sid, "S-1-5-")) {
                const char *name = v->data;
                if (user) { size_t length = static_cast<size_t>(end - host); while (length && host[length - 1] == '$') --length; name = ah_upper(g.arena, g.arena.copy(host, length)); }
                ah_track_resolved_call(g, name, sid, user ? "ReadUserProperties" : "ReadComputerProperties", "Success");
            }
            if (!first) { AH_TEXT(&b, ","); } first = false; ah_ref(b, sid, "Computer");
        }
        AH_TEXT(&b, "]");
        node.key("HasSIDHistory"); if (collect_props) ah_sid_history(g, b, o, true); else AH_TEXT(&b, "[]");
    }
    if (user) { node.key("SPNTargets"); ah_spn_targets(g, b, o); node.boolean("UnconstrainedDelegation", collect_props && (uac & 0x80000) != 0); node.nullable_text("DomainSID", wellknown ? nullptr : object_domain_sid); }
    if (computer) {
        node.boolean("IsDC", (uac & 0x2000) != 0); node.key("Status");
        if (o->hostavailability_checked && !o->host_connectable) {
            AH_TEXT(&b, "{\"Connectable\":"); if (o->host_connectable) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
            AH_TEXT(&b, ",\"Error\":"); if (o->host_connectable) AH_TEXT(&b, "null"); else ah_string(b, o->host_failure ? o->host_failure : "PortNotOpen"); AH_TEXT(&b, "}");
        } else AH_TEXT(&b, "null");
        node.key("DumpSMSAPassword"); AH_TEXT(&b, "[");
        bool first_smsa = true;
        for (ah_value *v = collect_props ? o->values("msDS-HostServiceAccount") : nullptr; v; v = v->next) {
            const char *id = nullptr, *kind = nullptr;
            if (ah_resolve_directory_dn(g, v->data, &id, &kind)) { if (!first_smsa) { AH_TEXT(&b, ","); } first_smsa = false; ah_ref(b, id, kind); }
        }
        AH_TEXT(&b, "]");
        node.key("AllowedToAct"); AH_TEXT(&b, "["); bool first = true;
        if (!ah_ad_rule_aces(collect_props ? o->values("msDS-AllowedToActOnBehalfOfOtherIdentity") : nullptr, [&](const ah_ace &ace) {
            if (ah_resolved_sid_kind(g, ace.sid)) { if (!first) { AH_TEXT(&b, ","); } first = false; ah_principal(g, b, ace.sid, false); }
        })) b.failed = true;
        AH_TEXT(&b, "]");
        node.key("Sessions"); ah_session_result(b, o->sessions, o->sessions_collected, o->id, o->sessions_failure_reason);
        node.key("PrivilegedSessions"); ah_session_result(b, o->privileged_sessions, o->privileged_collected, o->id, o->privileged_failure_reason);
        node.key("RegistrySessions"); ah_session_result(b, o->registry_sessions, o->registry_collected, o->id, o->registry_failure_reason);
        node.key("LocalGroups"); ah_local_groups_result(g, b, o);
        node.key("UserRights"); ah_user_rights_result(g, b, o);
        node.key("DCRegistryData"); AH_TEXT(&b, "{\"CertificateMappingMethods\":"); ah_registry_int_result(b, o->dc_registry_requested, o->cert_mapping_collected, o->cert_mapping_valid, o->cert_mapping, o->cert_mapping_failure);
        AH_TEXT(&b, ",\"StrongCertificateBindingEnforcement\":"); ah_registry_int_result(b, o->dc_registry_requested, o->strong_binding_collected, o->strong_binding_valid, o->strong_binding, o->strong_binding_failure);
        AH_TEXT(&b, ",\"VulnerableNetlogonSecurityDescriptor\":"); ah_registry_string_result(b, o->dc_registry_requested, o->vulnerable_netlogon_collected, o->vulnerable_netlogon, o->vulnerable_netlogon_failure); AH_TEXT(&b, "}");
        node.boolean("UnconstrainedDelegation", collect_props && (uac & 0x80000) != 0); node.nullable_text("DomainSID", wellknown ? nullptr : object_domain_sid);
        node.key("IsWebClientRunning");
        if (o->webclient_requested) ah_bool_api_result(b, o->webclient_collected, o->webclient_running, o->webclient_failure);
        else AH_TEXT(&b, "null");
        node.key("SmbInfo");
        if (!(ah_collection & AH_SMBINFO) || wellknown || !o->host_connectable) AH_TEXT(&b, "null");
        else if (o->smb_signing_collected) {
            AH_TEXT(&b, "{\"Result\":{\"SigningEnabled\":"); if (o->smb_signing) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
            AH_TEXT(&b, "},\"Collected\":true,\"FailureReason\":null}");
        } else {
            AH_TEXT(&b, "{\"Result\":null,\"Collected\":false,\"FailureReason\":");
            ah_string(b, o->host_failure ? o->host_failure : "SmbNegotiateFailed"); AH_TEXT(&b, "}");
        }
        node.key("NtlmSessions"); AH_TEXT(&b, "null");
        node.key("NTLMRegistryData"); ah_ntlm_registry_result(b, o);
    }
    if (group) {
        node.key("HasSIDHistory"); if (collect_props) ah_sid_history(g, b, o, true); else AH_TEXT(&b, "[]");
        node.key("Members"); AH_TEXT(&b, "["); bool first = true;
        for (ah_value *v = (ah_collection & AH_GROUP) && !wellknown ? o->values("member") : nullptr; v; v = v->next) {
            const char *id = nullptr, *kind = nullptr;
            if (!first) { AH_TEXT(&b, ","); } first = false;
            bool resolved=ah_group_member_identity(g,v->data,&id,&kind);
            if (resolved && !ah_filtered_sid(id)) { ah_mark_output_reference(g,id); ah_ref(b, id, kind); }
            else ah_ref(b, ah_upper(g.arena, v->data), "Base");
        }
        if (wellknown && ah_eq(o->raw_sid, "S-1-5-9")) {
            for (ah_object *member = g.directory.objects; member; member = member->next) if (!member->auxiliary_only && ah_eq(member->kind, "Computer") && (ah_unsigned(member->text("userAccountControl")) & 0x2000)) {
                if (!first) { AH_TEXT(&b, ","); } first = false; ah_ref(b, member);
            }
        }
        AH_TEXT(&b, "]");
    }
    if (domain) { node.key("Trusts"); ah_ad_trusts(g, b); node.key("ForestRootIdentifier"); if (ah_forest_root_id) ah_string(b, ah_forest_root_id); else AH_TEXT(&b, "null"); }
    if (domain || ou || container) {
        node.key("InheritanceHashes"); if (collect_acl) ah_inheritance_hashes(g, b, sd); else AH_TEXT(&b, "[]");
        node.key("ChildObjects"); AH_TEXT(&b, "[]");
    }
    if (domain || ou) {
        node.key("Links"); AH_TEXT(&b, "["); bool first = true;
        const char *p = collect_container ? o->text("gPLink") : "";
        while (*p) {
            while (*p && *p != '[') ++p;
            if (!*p) break;
            ++p;
            if (!ah_prefix(p, "LDAP://")) break;
            p += 7;
            const char *end = p, *separator = nullptr;
            while (*end && *end != ']') { if (*end == ';') separator = end; ++end; }
            if (!*end || !separator) break;
            uint64_t flags = ah_unsigned(separator + 1);
            const char *id = nullptr, *kind = nullptr;
            if (flags != 1 && flags != 3 && ah_resolve_directory_dn(g, g.arena.copy(p, static_cast<size_t>(separator - p)), &id, &kind)) {
                if (!first) { AH_TEXT(&b, ","); } first = false; AH_TEXT(&b, "{\"GUID\":"); ah_string(b, id);
                AH_TEXT(&b, ",\"IsEnforced\":"); if (flags == 2) AH_TEXT(&b, "true}"); else AH_TEXT(&b, "false}");
            }
            p = end + 1;
        }
        AH_TEXT(&b, "]");
        if ((ah_collection & AH_GPO_LOCAL_GROUP) && !o->gpo_changes) ah_collect_gpo_changes(g, o, ah_current_dc);
        node.key("GPOChanges"); ah_gpo_changes_result(g, b, o);
    }
    AH_TEXT(&b, "}");
}
static bool ah_ad_file(ah_graph &g, ah_buffer &b, const wchar_t *type, const char *name) {
    AH_TEXT(&b, "{\"data\":["); unsigned int count = 0;
    for (ah_object *o = g.directory.objects; o && !b.failed && !g.arena.failed; o = o->next) {
        bool oid_container = ah_weq(type, L"containers") && ah_weq(o->type, L"issuancepolicies") && ah_prefix(o->dn, "CN=OID,CN=Public Key Services");
        bool include = ah_output_selected(g, o) && (ah_weq(o->type, type) || (ah_weq(type, L"containers") && ah_weq(o->type, L"configuration")) || oid_container);
        if (include) { if (count++) AH_TEXT(&b, ","); ah_ad_node(g, b, o); }
    }
    AH_TEXT(&b, "],\"meta\":{"); ah_fields meta(b); meta.text("type", name); meta.number("count", count); meta.number("version", 6); meta.number("methods", ah_collection); meta.text("collectorversion", "AdaptiHound-BOF"); AH_TEXT(&b, "}}");
    return !b.failed && !g.arena.failed;
}
