#pragma once
#include "../../../common/output/zip.hpp"
#include "../core/collection.hpp"
#include "../collection/query_contract.hpp"

#include "../../../common/output/json.hpp"
static inline const char *ah_domain_dn(const char *dn) {
    for (const char *p = dn; *p; p = ah_parent(p)) {
        while (*p == ' ' || *p == '\t') ++p;
        if (ah_prefix(p, "DC=")) return p;
    }
    return "";
}
static const char *ah_trim_text(ah_arena &arena,const char *text) {
    if (!text) return nullptr;
    wchar_t *wide=ah_wide(text); if(!wide){arena.failed=true;return nullptr;}
    auto whitespace=[](wchar_t c){return (c>=9&&c<=13)||c==32||c==0x85||c==0xa0||c==0x1680||(c>=0x2000&&c<=0x200a)||c==0x2028||c==0x2029||c==0x202f||c==0x205f||c==0x3000;};
    wchar_t *start=wide,*end=wide+ah_wlen(wide);while(start<end&&whitespace(*start))++start;while(end>start&&whitespace(end[-1]))--end;*end=0;
    const char *result=start<end?arena.utf8(start):nullptr;ah_free(wide);return result;
}
static const char *ah_ad_kind(const wchar_t *type) {
    if (ah_weq(type, L"users")) return "User";
    if (ah_weq(type, L"computers")) return "Computer";
    if (ah_weq(type, L"groups")) return "Group";
    if (ah_weq(type, L"domains")) return "Domain";
    if (ah_weq(type, L"ous")) return "OU";
    if (ah_weq(type, L"gpos")) return "GPO";
    if (ah_weq(type, L"containers")) return "Container";
    if (ah_weq(type, L"configuration")) return "Container";
    if (ah_weq(type, L"sites")) return "Site";
    if (ah_weq(type, L"siteservers")) return "SiteServer";
    if (ah_weq(type, L"sitesubnets")) return "SiteSubnet";
    if (ah_weq(type, L"rootcas")) return "RootCA";
    if (ah_weq(type, L"aiacas")) return "AIACA";
    if (ah_weq(type, L"enterprisecas")) return "EnterpriseCA";
    if (ah_weq(type, L"ntauthstores")) return "NTAuthStore";
    if (ah_weq(type, L"certtemplates")) return "CertTemplate";
    if (ah_weq(type, L"issuancepolicies")) return "IssuancePolicy";
    return nullptr;
}
static const char *ah_wellknown_kind(const char *sid);
static bool ah_builtin(const char *sid) { return ah_wellknown_kind(sid) != nullptr; }
static const char *ah_wellknown_identifier_kind(const char *identifier, const char **raw_sid = nullptr) {
    if (!identifier) return nullptr;

    for (const char *candidate = identifier; *candidate; ++candidate) {
        if (candidate != identifier && candidate[-1] != '-') continue;
        if (ah_lower(candidate[0]) != 's' || candidate[1] != '-' || candidate[2] != '1' || candidate[3] != '-') continue;
        if (const char *kind = ah_wellknown_kind(candidate)) {
            if (raw_sid) *raw_sid = candidate;
            return kind;
        }
    }
    return nullptr;
}

struct ah_gpo_cache_entry;
struct ah_domain_name { const char *dn, *name; ah_domain_name *next; };
struct ah_target_computer { ah_object *object; ah_target_computer *next; };
struct ah_stealth_target_entry;
struct ah_graph;
struct ah_sid_kind_cache { const char *sid, *kind; ah_sid_kind_cache *next; };
struct ah_output_reference { const char *id; bool force; ah_output_reference *next; };
static const char *ah_target_host_sid(ah_graph &g, const char *host);
static const char *ah_resolved_sid_kind(ah_graph &g, const char *sid);
static bool ah_cache_type(const char*, const char**);
static bool ah_cached_unresolved(const char*);
static bool ah_output_selected(ah_graph&, const ah_object*);
static void ah_mark_output_reference(ah_graph&, const char*);
static void ah_record_output_reference(ah_graph&, const char*, bool);
static bool ah_resolve_directory_sid(ah_graph&, const char*, const char**, const char**);
static bool ah_resolve_directory_dn(ah_graph&, const char*, const char**, const char**);
static void *ah_create_worker_directory_runtime();
static void ah_destroy_worker_directory_runtime(void *);
static bool ah_worker_directory_runtime_required();
struct ah_graph final {
    ah_directory &directory;
    ah_arena &arena;
    ah_index dns, sids, hosts, principals, accounts;
    ah_object *root = nullptr;
    ah_sid_kind_cache *sid_kind_cache = nullptr;
    char *domain = nullptr;
    const char *forest_name = nullptr;
    const char *laps_guid = nullptr, *laps_guid_v2 = nullptr, *laps_guid_v3 = nullptr;
    ah_gpo_cache_entry *gpo_cache = nullptr;
    ah_domain_name *domain_names = nullptr;
    ah_target_computer *selected_computers = nullptr;
    bool computer_filter = false;
    ah_stealth_target_entry *stealth_targets = nullptr;
    bool stealth_targets_built = false;
    bool ad;
    bool parallel_worker = false;
    bool gpo_index_ready = false;
    void *directory_runtime = nullptr;
    ah_output_reference *output_references = nullptr;
    explicit ah_graph(ah_directory &data, bool windows_ad) : directory(data), arena(data.arena), ad(windows_ad) {}
    const char *forest_domain() {
        if (forest_name) return forest_name;
        for (ah_object *o = directory.objects; o; o = o->next) {
            if (ah_weq(o->type, L"forestmetadata")) {
                ah_object context = {}; context.dn = const_cast<char *>(o->text("nCName"));
                forest_name = object_domain(&context); return forest_name;
            }
        }
        for (ah_object *o = directory.objects; o; o = o->next) if (ah_weq(o->type, L"configuration")) {
            forest_name = object_domain(o); return forest_name;
        }
        return domain;
    }
    bool select_computers(const char *targets) {
        computer_filter = targets && *targets; selected_computers = nullptr;
        if (!computer_filter) return true;
        unsigned int found = 0, missing = 0;
        for (const char *p = targets; *p;) {
            while (*p == ',' || static_cast<unsigned char>(*p) <= 32) { if (!*p) break; ++p; }
            if (!*p) break;
            const char *end = p;
            while (*end && *end != ',' && *end != '\r' && *end != '\n') ++end;
            const char *trim = end;
            while (trim > p && static_cast<unsigned char>(trim[-1]) <= 32) --trim;
            while (p < trim && *p == '\\') ++p;
            while (trim > p && trim[-1] == '.') --trim;
            char *target = arena.copy(p, static_cast<size_t>(trim - p));
            if (!target) return false;
            ah_object *object = hosts.find(target);
            if (!object) object = sids.find(target);
            if (!object) object = accounts.find(target);
            if (!object) object = accounts.find(ah_concat(arena, target, "$"));
            if (!object && !ah_prefix(target, "S-1-")) {
                const char *sid = ah_target_host_sid(*this, target);
                if (sid) object = sids.find(sid);
            }
            if (!object || !ah_eq(object->kind, "Computer")) ++missing;
            else {
                bool duplicate = false;
                for (ah_target_computer *item = selected_computers; item; item = item->next) if (item->object == object) duplicate = true;
                if (!duplicate) {
                    ah_target_computer *item = arena.make<ah_target_computer>(); if (!item) return false;
                    item->object = object; item->next = selected_computers; selected_computers = item; ++found;
                }
            }
            p = end;
        }
        if (missing) BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: target selection: %u computers matched, %u names/SIDs unresolved", found, missing);
        else ah_log_telemetry("AdaptiHound: target selection: %u computers matched", found);
        return found != 0 && !arena.failed;
    }
    bool host_selected(const char *host) const {
        ah_object *computer = hosts.find(host);
        if (!computer_filter) return true;
        for (ah_target_computer *p = selected_computers; p; p = p->next) if (p->object == computer) return true;
        return false;
    }
    bool computer_selected(const ah_object *object) const {
        if (!computer_filter) return true;
        if (!ah_eq(object->kind, "Computer")) return !ah_eq(object->kind, "EnterpriseCA") || host_selected(object->text("dNSHostName"));
        for (ah_target_computer *p = selected_computers; p; p = p->next) if (p->object == object) return true;
        return false;
    }
    const char *object_domain(const ah_object *object) {
        if (!ad || !object || !object->dn) return domain;
        if (*object->text("__adaptihoundOwnerDomain")) return object->text("__adaptihoundOwnerDomain");
        if (object->raw_sid && ah_eq(object->raw_sid, "S-1-5-9")) return forest_domain();
        const char *suffix = ah_domain_dn(object->dn);
        if (!*suffix) return domain;
        if (root && ah_eq(suffix, ah_domain_dn(root->dn))) return domain;
        for (ah_domain_name *p = domain_names; p; p = p->next) if (ah_eq(p->dn, suffix)) return p->name;
        ah_buffer name(65536); bool first = true;
        for (const char *p = suffix; *p; p = ah_parent(p)) {
            while (*p == ' ' || *p == '\t') ++p;
            if (!ah_prefix(p, "DC=")) continue;
            if (!first) AH_TEXT(&name, ".");
            first = false;
            const char *next = ah_parent(p);
            const char *end = *next ? next - 1 : p + ah_len(p);
            for (const char *v = p + 3; v < end; ++v) {
                char byte = *v;
                if (byte == '\\' && v + 1 < end) {
                    auto hex = [](char c) -> int { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; };
                    int high = hex(v[1]), low = v + 2 < end ? hex(v[2]) : -1;
                    if (high >= 0 && low >= 0) { byte = static_cast<char>(high * 16 + low); v += 2; }
                    else byte = *++v;
                }
                ah_append(&name, &byte, 1);
            }
        }
        AH_TEXT(&name, "\0");
        if (name.failed) { arena.failed = true; return nullptr; }
        ah_domain_name *cached = arena.make<ah_domain_name>();
        if (!cached) return nullptr;
        cached->dn = suffix; cached->name = ah_upper(arena, name.data);
        cached->next = domain_names; domain_names = cached;
        return cached->name;
    }
    const char *object_domain_sid(const ah_object *object) {
        if (object && *object->text("__adaptihoundOwnerSID")) return object->text("__adaptihoundOwnerSID");
        const char *owner = object_domain(object);
        if (!owner) return nullptr;
        return ah_eq(owner, domain) ? (root ? root->id : nullptr) : ah_forest_root_id;
    }
    bool init(const wchar_t *base) {
        root = nullptr; gpo_cache = nullptr; domain_names = nullptr; forest_name = nullptr; sid_kind_cache = nullptr;
        stealth_targets = nullptr; stealth_targets_built = false;
        laps_guid = laps_guid_v2 = laps_guid_v3 = nullptr;
        size_t principal_count = 0;
        for (ah_object *o = directory.objects; o; o = o->next) for (ah_value *v = o->values("servicePrincipalName"); v; v = v->next) ++principal_count;
        char *dn = arena.utf8(base);
        if (!dn) return false;
        ah_buffer name(65536); bool first = true;
        for (const char *p = dn; *p; p = ah_parent(p)) {
            if (ah_prefix(p, "DC=")) {
                if (!first) { AH_TEXT(&name, "."); }
                first = false;
                const char *end = p + 3; while (*end && *end != ',') ++end;
                ah_append(&name, p + 3, static_cast<size_t>(end - p - 3));
            }
        }
        AH_TEXT(&name, "\0");
        if (name.failed) return false;
        domain = ah_upper(arena, name.data);
        if (!domain) return false;
        const char *forest = ad ? forest_domain() : domain;
        if (forest && !ah_eq(forest, domain)) {
            ah_object *last = directory.tail;
            for (ah_object *o = directory.objects; o; o = o->next) {
                ah_value *value = o->values("objectSid"); char sid[192];
                if (!*o->text("__adaptihoundOwnerDomain") && value && ah_sid_string(sid, reinterpret_cast<unsigned char *>(value->data), value->size) && ah_builtin(sid) && !ah_eq(sid, "S-1-5-9")) {
                    bool found = false;
                    for (ah_object *p = directory.objects; p; p = p->next) {
                        if (!ah_eq(p->text("__adaptihoundOwnerDomain"), forest)) continue;
                        ah_value *other = p->values("objectSid"); char existing[192];
                        if (other && ah_sid_string(existing, reinterpret_cast<unsigned char *>(other->data), other->size) && ah_eq(sid, existing)) { found = true; break; }
                    }
                    if (!found) {
                        const char *kind = ah_wellknown_kind(sid);
                        ah_object *copy = directory.add(ah_eq(kind, "User") ? L"users" : ah_eq(kind, "Computer") ? L"computers" : L"groups", "");
                        if (!copy) return false;
                        directory.value(directory.attribute(copy, "objectSid"), value->data, value->size);
                        const char *account = o->text("sAMAccountName", sid);
                        directory.value(directory.attribute(copy, "sAMAccountName"), account, ah_len(account));
                        directory.value(directory.attribute(copy, "__adaptihoundOwnerDomain"), forest, ah_len(forest));
                        if (ah_forest_root_id) directory.value(directory.attribute(copy, "__adaptihoundOwnerSID"), ah_forest_root_id, ah_len(ah_forest_root_id));
                    }
                }
                if (o == last) break;
            }
        }
        if (!dns.init(arena, directory.count) || !sids.init(arena, directory.count) || !hosts.init(arena, directory.count) || !principals.init(arena, principal_count) || !accounts.init(arena, directory.count * 2)) return false;
        for (ah_object *o = directory.objects; o && !arena.failed; o = o->next) {
            o->kind = ah_ad_kind(o->type);
            if (ad && ah_weq(o->type, L"configuration") && ah_has(o,"objectClass","configuration")) o->kind="Configuration";
            if (ad && ah_weq(o->type, L"issuancepolicies")) {

                o->kind = ah_prefix(o->dn, "CN=OID,CN=Public Key Services,CN=Services") ? "Container" :
                    (ah_unsigned(o->text("flags")) == 2 ? "IssuancePolicy" : nullptr);
            }
            if (ad && ah_weq(o->type, L"schema")) {
                ah_value *v = o->values("schemaIDGUID");
                if (v && ah_eq(o->text("lDAPDisplayName"), "ms-mcs-admpwd")) laps_guid = ah_guid(arena, reinterpret_cast<unsigned char *>(v->data), v->size);
                if (v && ah_eq(o->text("lDAPDisplayName"), "msLAPS-Password")) laps_guid_v2 = ah_guid(arena, reinterpret_cast<unsigned char *>(v->data), v->size);
                if (v && ah_eq(o->text("lDAPDisplayName"), "msLAPS-EncryptedPassword")) laps_guid_v3 = ah_guid(arena, reinterpret_cast<unsigned char *>(v->data), v->size);
            }
            if(ad&&ah_eq(o->kind,"Computer")&&!o->values("dNSHostName")) {

                o->synthesized_dns_name=true;
                const char *short_name=o->text("sAMAccountName",nullptr);size_t length=ah_len(short_name);
                while(length&&short_name[length-1]=='$')--length;
                if(!short_name||!ah_trim_text(arena,arena.copy(short_name,length))) {
                    short_name=o->text("cn",o->text("name","UNKNOWN"));length=ah_len(short_name);
                }
                const char *host=ah_concat(arena,arena.copy(short_name,length),".",object_domain(o));
                ah_attr *attribute=directory.attribute(o,"dNSHostName");
                if(host&&attribute){attribute->values=attribute->tail=nullptr;directory.value(attribute,host,ah_len(host));}
            }
            o->exported = !o->auxiliary_only && o->kind && (o->explicit_target || ah_query_enabled(o->type, ah_collection));
            if (ah_weq(o->type, L"domains")) {
                if (root) return false;
                root = o;
            }
            if (ad) {
                ah_value *value = o->values("objectSid");
                if (value) o->raw_sid = ah_sid(arena, reinterpret_cast<unsigned char *>(value->data), value->size);
                value = o->values("objectGUID");
                const bool builtin_domain = ah_has(o, "objectClass", "builtinDomain");
                o->id = o->raw_sid && !builtin_domain ? (ah_builtin(o->raw_sid) ? ah_concat(arena, object_domain(o), "-", o->raw_sid) : o->raw_sid) : (value ? ah_guid(arena, reinterpret_cast<unsigned char *>(value->data), value->size) : nullptr);
            }
            if (o->exported && !o->id) return false;
            if (*o->dn) dns.put(o->dn, o);
            if (o->id) sids.put(o->id, o);
            if (o->raw_sid && (!ah_builtin(o->raw_sid) || ah_eq(object_domain(o), domain) || ah_eq(o->raw_sid, "S-1-5-9"))) sids.put(o->raw_sid, o);
            if (ad && *o->dn && o->raw_sid && (!ah_builtin(o->raw_sid) || ah_eq(object_domain(o), domain) || ah_eq(o->raw_sid, "S-1-5-9"))) {
                accounts.put(o->text("sAMAccountName"), o);
                accounts.put(o->text("msDS-PrincipalName"), o);
            }
            if (ah_weq(o->type, L"computers") && (!ad || *o->dn)) {
                hosts.put(o->text("dNSHostName"), o);
                if (ad) {
                    const char *account = o->text("sAMAccountName"); size_t n = ah_len(account);
                    hosts.put(arena.copy(account, n && account[n - 1] == '$' ? n - 1 : n), o);
                }
            }
            for (ah_value *v = o->values("servicePrincipalName"); v; v = v->next) principals.put(v->data, o);
        }
        if (!root || !root->id || !domain || !*domain || arena.failed) return false;

        for (ah_object *o = directory.objects; o; o = o->next) o->parent = o->children = o->sibling = nullptr;
        for (ah_object *o = directory.objects; o; o = o->next) {
            o->parent = dns.find(ah_parent(o->dn));
            if (o->parent && o->exported) { o->sibling = o->parent->children; o->parent->children = o; }
        }
        return true;
    }
};

static void ah_ref(ah_buffer &b, const char *id, const char *kind) {
    AH_TEXT(&b, "{\"ObjectIdentifier\":"); ah_string(b, id);
    AH_TEXT(&b, ",\"ObjectType\":"); ah_string(b, kind); AH_TEXT(&b, "}");
}
static void ah_ref(ah_buffer &b, const ah_object *o) { if (o && o->id) ah_ref(b, o->id, o->kind ? o->kind : "Base"); else AH_TEXT(&b, "null"); }
static void ah_principal(ah_graph &g, ah_buffer &b, const char *sid, bool ace, const char *right = nullptr, bool inherited = false, const char *inheritance_hash = nullptr, const char *principal_domain = nullptr) {
    ah_object *o = g.sids.find(sid);
    if (!principal_domain) principal_domain = g.domain;
    if (ah_eq(sid, "S-1-5-9")) principal_domain = g.forest_domain();
    const char *known_kind = ah_resolved_sid_kind(g, sid);
    if (ah_builtin(sid) && !ah_eq(principal_domain, g.domain)) o = nullptr;
    char qualified[512]; const char *id = sid, *kind = "Base";
    if (o) { id = o->id; kind = known_kind ? known_kind : "Base"; }
    else if (ah_builtin(sid)) {
        size_t n = 0;
        for (const char *p = principal_domain; *p && n + 1 < sizeof(qualified); ++p) qualified[n++] = *p;
        qualified[n++] = '-';
        for (const char *p = sid; *p && n + 1 < sizeof(qualified); ++p) qualified[n++] = *p;
        qualified[n] = 0; id = qualified;
        kind = known_kind ? known_kind : ah_wellknown_kind(sid);
    } else if (known_kind) kind = known_kind;
    if (ah_builtin(sid)) {
        ah_object *principal = g.sids.find(id);
        if (principal) ah_mark_output_reference(g,id);
    }
    if (!ace) { ah_ref(b, id, kind); return; }
    AH_TEXT(&b, "{"); ah_fields fields(b);
    fields.text("PrincipalSID", id); fields.text("PrincipalType", kind); fields.text("RightName", right);
    fields.boolean("IsInherited", inherited);
    fields.nullable_text("InheritanceHash", inheritance_hash);
    const bool owner_rights = inheritance_hash && right && !ah_eq(right, "Owns") && !ah_eq(right, "ReadGMSAPassword") && ah_eq(sid, "S-1-3-4");
    fields.boolean("IsPermissionForOwnerRightsSid", owner_rights);
    fields.boolean("IsInheritedPermissionForOwnerRightsSid", inherited && owner_rights);
    AH_TEXT(&b, "}");
}
static bool ah_try_int64_text(const char *text, int64_t &out) {
    if (!text) return false;
    while (*text == ' ' || (*text >= '\t' && *text <= '\r')) ++text;
    bool negative = *text == '-'; if (*text == '-' || *text == '+') ++text;
    if (*text < '0' || *text > '9') return false;
    uint64_t value=0, maximum=negative ? (1ULL<<63) : 9223372036854775807ULL;
    while (*text >= '0' && *text <= '9') { unsigned int digit=static_cast<unsigned int>(*text++-'0'); if(value>(maximum-digit)/10)return false; value=value*10+digit; }
    while (*text == ' ' || (*text >= '\t' && *text <= '\r')) ++text;
    if (*text) return false;
    out=negative ? value==(1ULL<<63) ? (-9223372036854775807LL-1) : -static_cast<int64_t>(value) : static_cast<int64_t>(value);
    return true;
}
static bool ah_try_property_long(const ah_object *o,const char *attribute,int64_t &out) { return ah_try_int64_text(o->text(attribute,nullptr),out); }
static int64_t ah_time(const ah_object *o, const char *name, bool generalized = false) {
    const char *text = o->text(name);
    if (!*text) return -1;
    if (!generalized) {
        int64_t ticks = 0;

        if (!ah_try_int64_text(text, ticks) || ticks < 0 || ticks > 2650467743999999999LL) return -1;
        if (!ticks) return 0;
        const double seconds = static_cast<double>(ticks - 116444736000000000LL) / 10000000.0;
        const int64_t whole = static_cast<int64_t>(seconds);
        return seconds < static_cast<double>(whole) ? whole - 1 : whole;
    }
    if (ah_len(text) != 17 || text[14] != '.' || text[15] != '0' || text[16] != 'Z') return 0;
    unsigned int numbers[6] = {}, lengths[6] = {4,2,2,2,2,2}; size_t p = 0;
    for (unsigned int i = 0; i < 6; ++i) for (unsigned int j = 0; j < lengths[i]; ++j) {
        if (text[p] < '0' || text[p] > '9') return 0;
        numbers[i] = numbers[i] * 10 + static_cast<unsigned int>(text[p++] - '0');
    }
    SYSTEMTIME st = {}; st.wYear = static_cast<WORD>(numbers[0]); st.wMonth = static_cast<WORD>(numbers[1]); st.wDay = static_cast<WORD>(numbers[2]);
    st.wHour = static_cast<WORD>(numbers[3]); st.wMinute = static_cast<WORD>(numbers[4]); st.wSecond = static_cast<WORD>(numbers[5]);
    FILETIME ft = {};
    if (!KERNEL32$SystemTimeToFileTime(&st, &ft)) return 0;
    uint64_t n = static_cast<uint64_t>(ft.dwHighDateTime) << 32 | ft.dwLowDateTime;
    return static_cast<int64_t>(n / 10000000ULL) - 11644473600LL;
}

static bool ah_extra_reserved(const char *name) {
    if (ah_prefix(name, "__adaptihound")) return true;
    if (ah_eq(name, "dSASignature")) return true;
    wchar_t wide[256]; size_t length=ah_len(name); if(length>=256)return false;
    for(size_t i=0;i<=length;++i)wide[i]=static_cast<unsigned char>(name[i]);
    return ah_query_attribute_enabled(wide,AH_ALL,false)||ah_query_attribute_enabled(wide,AH_ALL,true);
}
static bool ah_bool_whitespace(wchar_t c) {

    return c == 0 || (c >= 9 && c <= 13) || c == 32 || c == 0x85 || c == 0xa0 || c == 0x1680 ||
        (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f || c == 0x3000;
}
static void ah_extra_value(ah_graph &g, ah_buffer &b, const char *attribute, const ah_value *value) {

    int count=KERNEL32$MultiByteToWideChar(CP_UTF8,0,value->data,static_cast<int>(value->size),nullptr,0);
    wchar_t *wide=count>0?ah_alloc<wchar_t>((static_cast<size_t>(count)+1)*sizeof(wchar_t)):nullptr;
    if (!wide) { if(!value->size){ah_string(b,"");return;} b.failed=true;return; }
    if(!KERNEL32$MultiByteToWideChar(CP_UTF8,0,value->data,static_cast<int>(value->size),wide,count)){ah_free(wide);b.failed=true;return;}
    wide[count]=0;
    int bytes=KERNEL32$WideCharToMultiByte(CP_UTF8,0,wide,count,nullptr,0,nullptr,nullptr);
    char *decoded=bytes>=0?ah_alloc(static_cast<size_t>(bytes)+1):nullptr;
    if(!decoded){ah_free(wide);b.failed=true;return;}
    if(bytes&&!KERNEL32$WideCharToMultiByte(CP_UTF8,0,wide,count,decoded,bytes,nullptr,nullptr)){ah_free(wide);ah_free(decoded);b.failed=true;return;}
    decoded[bytes]=0;
    bool control=false;for(int i=0;i<count;++i)if(wide[i]<32||(wide[i]>=127&&wide[i]<=159))control=true;
    bool scalar=static_cast<size_t>(bytes)==ah_len(decoded);
    int begin=0,end=count;
    while(begin<end&&ah_bool_whitespace(wide[begin]))++begin;
    while(end>begin&&ah_bool_whitespace(wide[end-1]))--end;
    auto word = [&](const char *expected) {
        const size_t length=ah_len(expected);
        if(static_cast<size_t>(end-begin)!=length)return false;
        for(size_t i=0;i<length;++i)if(wide[begin+i]>127||ah_lower(static_cast<char>(wide[begin+i]))!=expected[i])return false;
        return true;
    };
    bool is_true=word("true"),is_false=word("false");
    if(attribute&&ah_eq(attribute,"badPasswordTime")&&scalar){
        ah_value v={decoded,static_cast<size_t>(bytes),nullptr};ah_attr a={const_cast<char*>("time"),&v,&v,nullptr};ah_object o={};o.attributes=&a;
        ah_int64(b,ah_time(&o,"time"));
    } else if(is_true) AH_TEXT(&b,"true");
    else if(is_false) AH_TEXT(&b,"false");
    else if(scalar&&bytes>=2&&decoded[bytes-2]=='0'&&decoded[bytes-1]=='Z'){
        ah_value v={decoded,static_cast<size_t>(bytes),nullptr};ah_attr a={const_cast<char*>("time"),&v,&v,nullptr};ah_object o={};o.attributes=&a;
        ah_int64(b,ah_time(&o,"time",true));
    } else if(scalar&&ah_eq(decoded,"9223372036854775807")) AH_TEXT(&b,"-1");
    else {
        int64_t number=0;
        if(scalar&&ah_try_int64_text(decoded,number)&&number>=-2147483648LL&&number<=2147483647LL)ah_int64(b,number);
        else if(control){
            DWORD length=0;
            if(!CRYPT32$CryptBinaryToStringA(reinterpret_cast<const BYTE*>(decoded),static_cast<DWORD>(bytes),CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,nullptr,&length))b.failed=true;
            else {char *encoded=ah_alloc(length);if(!encoded)b.failed=true;else{if(!CRYPT32$CryptBinaryToStringA(reinterpret_cast<const BYTE*>(decoded),static_cast<DWORD>(bytes),CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,encoded,&length))b.failed=true;else ah_string(b,encoded);ah_free(encoded);}}
        } else ah_json_bytes(&b,decoded,static_cast<size_t>(bytes));
    }
    ah_free(decoded);ah_free(wide);(void)g;
}
static void ah_extra_properties(ah_graph &g, ah_buffer &b, ah_fields &props, const ah_object *object) {
    if (!ah_collect_all_properties) return;
    for (ah_attr *attribute=object->attributes;attribute&&!b.failed;attribute=attribute->next) {
        if(!attribute->values||ah_extra_reserved(attribute->name)||props.contains(attribute->name))continue;
        const bool array=attribute->values->next!=nullptr;
        if(!array&&!attribute->values->size)continue;
        char *key=g.arena.copy(attribute->name);if(!key)return;for(char *p=key;*p;++p)*p=ah_lower(*p);
        props.key(key);
        if(array){
            ah_value *first=attribute->values;char sid[192],guid[37];
            if(ah_sid_string(sid,reinterpret_cast<unsigned char*>(first->data),first->size)){ah_string(b,sid);continue;}
            if(first->size==16&&ah_guid_string(guid,reinterpret_cast<unsigned char*>(first->data),first->size)){for(char *p=guid;*p;++p)*p=ah_lower(*p);ah_string(b,guid);continue;}
            AH_TEXT(&b,"[");
        }
        bool first=true;
        for(ah_value *v=attribute->values;v;v=v->next){if(!first){AH_TEXT(&b,",");}first=false;ah_extra_value(g,b,array?nullptr:attribute->name,v);}
        if(array)AH_TEXT(&b,"]");
    }
}

static bool ah_group_member_identity(ah_graph &g,const char *dn,const char **id,const char **kind) {
    ah_object *known=g.dns.find(dn);
    if(known&&known->raw_sid&&(!known->kind||ah_eq(known->kind,"Base")))return ah_resolve_directory_sid(g,known->raw_sid,id,kind);
    return ah_resolve_directory_dn(g,dn,id,kind);
}
static bool ah_directory_ref(ah_graph &g, ah_buffer &b, const char *dn, const char *required_kind = nullptr) {
    const char *id = nullptr, *kind = nullptr;
    if (dn && *dn && ah_resolve_directory_dn(g, dn, &id, &kind) && (!required_kind || ah_eq(kind, required_kind))) { ah_ref(b, id, kind); return true; }
    AH_TEXT(&b, "null"); return false;
}
static const wchar_t *ah_current_dc = nullptr;

static void ah_common_object_properties(ah_graph &g, ah_buffer &b, ah_fields &props, const ah_object *o) {
    props.key("objectclass"); ah_text_array(b, o->values("objectClass"));
    if (o->values("description")) props.text("description", o->text("description"));
    if (o->values("whenCreated")) props.number("whencreated", ah_time(o, "whenCreated", true));
    ah_value *value = o->values("objectGUID"); char guid[37];
    if (value && value->size == 16 && ah_guid_string(guid, reinterpret_cast<unsigned char *>(value->data), value->size))
        props.text("objectguid", ah_upper(g.arena, guid));
    (void)g;
}
static bool ah_has_laps(const ah_object *o) {
    return ah_signed(o->text("msLAPS-PasswordExpirationTime")) > 0 || ah_signed(o->text("ms-Mcs-AdmPwdExpirationTime")) > 0;
}

#include "duration.hpp"
#include "../registry/rights_registry.hpp"
#include "../host/sessions.hpp"
static const char *ah_resolved_sid_kind(ah_graph &g, const char *sid) {
    if (const char *kind = ah_wellknown_identifier_kind(sid)) return kind;
    if (ah_cached_unresolved(sid)) return nullptr;
    const char *cached = nullptr;
    if (ah_cache_type(sid, &cached)) return cached;
    ah_object *known = g.sids.find(sid);
    if (known && known->kind) return known->kind;
    for (ah_sid_kind_cache *p = g.sid_kind_cache; p; p = p->next) if (ah_eq(p->sid, sid)) return p->kind;
    const char *kind = nullptr, *id = nullptr;
    if (!ah_resolve_directory_sid(g, sid, &id, &kind)) kind = nullptr;
    ah_sid_kind_cache *entry = g.arena.make<ah_sid_kind_cache>();
    if (entry) { entry->sid = g.arena.copy(sid); entry->kind = kind; entry->next = g.sid_kind_cache; g.sid_kind_cache = entry; }
    return kind;
}
static const char *ah_target_host_sid(ah_graph &g, const char *host) {
    if (ah_eq(host, "localhost") || ah_eq(host, "127.0.0.1") || ah_eq(host, "::1") || ah_eq(host, "[::1]")) {
        ah_native_library kernel(L"kernel32.dll");
        auto computer_name = kernel.find<decltype(&GetComputerNameExW)>("GetComputerNameExW");
        const COMPUTER_NAME_FORMAT formats[] = {ComputerNameDnsFullyQualified, ComputerNameNetBIOS};
        if (computer_name) for (COMPUTER_NAME_FORMAT format : formats) {
            wchar_t name[256]; DWORD length = 256;
            if (computer_name(format, name, &length)) if (ah_object *computer = g.hosts.find(g.arena.utf8(name))) return computer->id;
        }
        return nullptr;
    }
    wchar_t *wide = ah_wide(host);
    ah_object context = {};
    const char *sid = wide ? ah_session_host_sid(g, &context, wide) : nullptr;
    ah_free(wide);
    return sid;
}
#include "../host/targeting.hpp"
#include "../host/probes.hpp"
#include "../host/host_pool.hpp"
#include "gpo.hpp"
#include "ad_graph.hpp"
#include "site_graph.hpp"
#include "enrollment.hpp"
#include "adcs_graph.hpp"

static bool ah_output_selected(ah_graph &g, const ah_object *o) {
    if (!o->exported || o->consumer_failed) return false;

    if (!*o->dn && ah_eq(o->raw_sid,"S-1-5-9")) {
        bool has_members=false;
        for (const ah_object *member=g.directory.objects;member;member=member->next)
            if (!member->auxiliary_only && ah_eq(member->kind,"Computer") && (ah_unsigned(member->text("userAccountControl"))&0x2000)) {has_members=true;break;}
        if (!has_members) return false;
    }
    if (!ah_computer_file_mode || !*o->dn) return true;
    return o->explicit_target;
}
static bool ah_dataset_has_rows(ah_graph &g, const wchar_t *type) {
    for (ah_object *o = g.directory.objects; o; o = o->next) {
        if (!ah_output_selected(g, o)) continue;
        if (ah_weq(o->type, type)) {
            if (ah_weq(type, L"issuancepolicies") && !ah_eq(o->kind, "IssuancePolicy")) continue;
            return true;
        }
        if (ah_weq(type, L"containers") && (ah_weq(o->type, L"configuration") || (ah_weq(o->type,L"issuancepolicies") && ah_eq(o->kind,"Container")))) return true;
    }
    return false;
}
static void ah_record_output_reference(ah_graph &g, const char *id, bool force) {
    ah_object *o = id ? g.sids.find(id) : nullptr;
    if (!o || !ah_builtin(o->raw_sid)) return;
    if (!g.parallel_worker) { o->exported = true; return; }

    for (auto *old=g.output_references;old;old=old->next) if(old->id==o->id) { old->force=old->force||force;return; }
    auto *reference=g.arena.make<ah_output_reference>();
    if(!reference)return;
    reference->id=o->id;reference->force=force;reference->next=g.output_references;g.output_references=reference;
}
static void ah_mark_output_reference(ah_graph &g, const char *id) { ah_record_output_reference(g,id,false); }
[[maybe_unused]] static bool ah_prepare_output_graph(ah_graph &g) {

    for (ah_object *o = g.directory.objects; o; o = o->next) if (!*o->dn && ah_builtin(o->raw_sid)) o->exported = false;
    ah_buffer discard(16 * 1024 * 1024);
    for (ah_object *o = g.directory.objects; o && !g.arena.failed; o = o->next) {
        if (!*o->dn || !ah_output_selected(g, o)) continue;
        const bool adcs = ah_eq(o->kind,"RootCA") || ah_eq(o->kind,"AIACA") || ah_eq(o->kind,"EnterpriseCA") || ah_eq(o->kind,"NTAuthStore") || ah_eq(o->kind,"CertTemplate") || ah_eq(o->kind,"IssuancePolicy");
        const bool site = ah_eq(o->kind,"Site") || ah_eq(o->kind,"SiteServer") || ah_eq(o->kind,"SiteSubnet");
        if ((ah_collection & AH_ACL) || ((ah_collection & AH_CERT_SERVICES) && (adcs || ah_eq(o->kind,"Container") || ah_eq(o->kind,"Configuration"))) || ((ah_collection & AH_SITE) && site)) {
            discard.length = 0; ah_ad_acl(g, discard, o); if (discard.failed) return false;
        }
        if ((ah_collection & AH_OBJECT_PROPS) && (ah_eq(o->kind,"User") || ah_eq(o->kind,"Computer") || ah_eq(o->kind,"Group"))) {
            discard.length = 0; ah_sid_history(g, discard, o, true); if (discard.failed) return false;
            if (ah_eq(o->kind,"Computer") && !ah_ad_rule_aces(o->values("msDS-AllowedToActOnBehalfOfOtherIdentity"),[&](const ah_ace &ace) {
                if (ah_resolved_sid_kind(g,ace.sid)) { discard.length=0; ah_principal(g,discard,ace.sid,false); }
            })) return false;
        }
        if ((ah_collection & AH_GROUP) && ah_eq(o->kind,"Group")) for (ah_value *v = o->values("member"); v; v = v->next) {
            const char *id=nullptr,*kind=nullptr;
            if (ah_group_member_identity(g,v->data,&id,&kind) && !ah_filtered_sid(id)) ah_mark_output_reference(g,id);
        }
        if ((ah_collection & AH_GPO_LOCAL_GROUP) && (ah_eq(o->kind,"Domain") || ah_eq(o->kind,"OU"))) {
            if (!o->gpo_changes) ah_collect_gpo_changes(g,o,ah_current_dc);
            if (o->gpo_changes) {
                ah_session_info *sets[] = {o->gpo_changes->local_admins,o->gpo_changes->remote_desktop_users,o->gpo_changes->dcom_users,o->gpo_changes->psremote_users};
                for (ah_session_info *set : sets) for (;set;set=set->next) {
                    ah_object *known=g.sids.find(set->sid);
                    if (known) ah_mark_output_reference(g,known->id);
                    else if (ah_builtin(set->sid)) { discard.length=0; ah_principal(g,discard,set->sid,false); }
                }
            }
        }
        if (ah_eq(o->kind,"Computer")) {
            const ah_local_group_info *sets[] = {o->local_groups,o->user_rights};
            for (const ah_local_group_info *set : sets) for (;set;set=set->next) for (ah_session_info *member=set->members;member;member=member->next) {
                const char *kind=nullptr; ah_mark_output_reference(g,ah_local_member_id(g,o,member->sid,member->usage,&kind));
            }
            if (ah_integer(o,"userAccountControl") & 0x2000) {
                const char *id=ah_concat(g.arena,g.forest_domain(),"-","S-1-5-9"); ah_mark_output_reference(g,id);
            }
        }
        if (ah_eq(o->kind,"EnterpriseCA") && (ah_collection & AH_CA_REGISTRY) && g.host_selected(o->text("dNSHostName"))) {
            if (!o->ca_registry_requested) ah_collect_ca_registry(g,o);
            if (o->ca_security_collected && o->ca_security) { discard.length=0; ah_ca_registry_acl(g,discard,o); if(discard.failed)return false; }
            if (o->enrollment_agent_collected && o->enrollment_agent_rights) { discard.length=0; ah_enrollment_restrictions(g,discard,o); if(discard.failed)return false; }
        }
    }
    return !g.arena.failed;
}

#include "../../../common/output/archive_output.hpp"
#include "combined_output.hpp"
#include "object_pool.hpp"

static const char *ah_output_dataset(const ah_object *object) {
    if(ah_weq(object->type,L"configuration") ||
       (ah_weq(object->type,L"issuancepolicies") && ah_eq(object->kind,"Container")))return "containers";
    static const wchar_t *types[]={L"users",L"computers",L"groups",L"domains",L"ous",L"gpos",L"containers",L"rootcas",L"aiacas",L"enterprisecas",L"ntauthstores",L"certtemplates",L"issuancepolicies",L"sites",L"siteservers",L"sitesubnets"};
    static const char *names[]={"users","computers","groups","domains","ous","gpos","containers","rootcas","aiacas","enterprisecas","ntauthstores","certtemplates","issuancepolicies","sites","siteservers","sitesubnets"};
    for(size_t i=0;i<sizeof(types)/sizeof(types[0]);++i)if(ah_weq(object->type,types[i])) {
        if(i==12&&!ah_eq(object->kind,"IssuancePolicy"))return nullptr;
        return names[i];
    }
    return nullptr;
}
static bool ah_parallel_output_selected(ah_graph &graph,const ah_object *object) {
    return !object->auxiliary_only && *object->dn && ah_output_selected(graph,object) && ah_output_dataset(object);
}
static bool ah_serialize_output_object(ah_graph &graph,ah_object *object,ah_buffer &json) {
    if(object->consumer_failed)return true;
    const char *dataset=ah_output_dataset(object);
    if(!dataset)return false;
    if(ah_eq(object->kind,"Computer")&&(ah_integer(object,"userAccountControl")&0x2000))
        ah_mark_output_reference(graph,ah_concat(graph.arena,graph.forest_domain(),"-S-1-5-9"));
    if(ah_eq(dataset,"sites")||ah_eq(dataset,"siteservers")||ah_eq(dataset,"sitesubnets"))ah_site_node(graph,json,object);
    else if(ah_eq(dataset,"rootcas")||ah_eq(dataset,"aiacas")||ah_eq(dataset,"enterprisecas")||ah_eq(dataset,"ntauthstores")||ah_eq(dataset,"certtemplates")||ah_eq(dataset,"issuancepolicies"))ah_adcs_node(graph,json,object,ah_collection);
    else ah_ad_node(graph,json,object);
    return !json.failed&&!graph.arena.failed;
}
struct ah_parallel_output_context { ah_graph &source;ah_combined_output &output; };
static bool ah_capture_output_object(void *opaque,const ah_object *object,const ah_buffer &json,ah_graph &local) {
    if(object->consumer_failed)return true;
    auto &context=*static_cast<ah_parallel_output_context*>(opaque);
    const char *dataset=ah_output_dataset(object);
    if(!dataset||!context.output.capture_row(dataset,object->id,*object->dn!=0,ah_eq(object->raw_sid,"S-1-5-9"),json))return false;

    for(auto *reference=local.output_references;reference;reference=reference->next) {
        ah_output_reference *old=context.source.output_references;
        for(;old;old=old->next)if(old->id==reference->id)break;
        if(old)old->force=old->force||reference->force;
        else {
            auto *copy=context.source.arena.make<ah_output_reference>();if(!copy)return false;
            *copy=*reference;copy->next=context.source.output_references;context.source.output_references=copy;
        }
    }
    if(!context.output.capture_calls(local.directory)||context.source.arena.failed)return false;
    ah_observe_object_completed();
    ah_log_level(0,"Consumer completed %s (%s)",object->id,object->kind);
    return true;
}
static bool ah_export_ad_objects(ah_graph &graph,size_t limit,const wchar_t *dc) {
    if(!ah_active_combined_output)return false;
    for(ah_object *object=graph.directory.objects;object;object=object->next)
        if(!*object->dn&&ah_builtin(object->raw_sid))object->exported=false;
    if((ah_collection&AH_GPO_LOCAL_GROUP)&&!ah_prepare_gpo_output(graph,dc))return false;
    ah_parallel_output_context context{graph,*ah_active_combined_output};
    ah_object_pool pool(graph,limit);
    const bool diagnostics=ah_host_diagnostics;ah_host_diagnostics=diagnostics && ah_telemetry_enabled;
    const bool success=pool.run(graph.directory.objects,ah_threads,ah_parallel_output_selected,ah_serialize_output_object,ah_capture_output_object,&context);
    ah_host_diagnostics=diagnostics;
    if(!success){BeaconPrintf(CALLBACK_ERROR,"AdaptiHound: object processing failed (worker status %u)",pool.error());return false;}

    for(auto *reference=graph.output_references;reference;reference=reference->next)
        ah_record_output_reference(graph,reference->id,reference->force);
    for(ah_object *object=graph.directory.objects;object;object=object->next) {
        ah_object placeholder={};
        ah_value name_value={},domain_value={},sid_value={};
        ah_attr name_attribute={},domain_attribute={},sid_attribute={};
        ah_object *emitted=object;
        if(*object->dn) {
            if(!object->exported||!ah_builtin(object->raw_sid))continue;

            const char *name=ah_wellknown_name(object->raw_sid);
            const char *domain=graph.object_domain(object),*sid=graph.object_domain_sid(object);
            name_value={const_cast<char *>(name?name:object->raw_sid),ah_len(name?name:object->raw_sid),nullptr};
            domain_value={const_cast<char *>(domain),ah_len(domain),nullptr};
            sid_value={const_cast<char *>(sid?sid:""),ah_len(sid),nullptr};
            name_attribute={const_cast<char *>("sAMAccountName"),&name_value,&name_value,&domain_attribute};
            domain_attribute={const_cast<char *>("__adaptihoundOwnerDomain"),&domain_value,&domain_value,&sid_attribute};
            sid_attribute={const_cast<char *>("__adaptihoundOwnerSID"),&sid_value,&sid_value,nullptr};
            placeholder.dn=const_cast<char *>("");placeholder.id=object->id;placeholder.raw_sid=object->raw_sid;
            placeholder.kind=ah_wellknown_kind(object->raw_sid);placeholder.exported=true;placeholder.attributes=&name_attribute;
            placeholder.type=ah_eq(placeholder.kind,"User")?L"users":ah_eq(placeholder.kind,"Computer")?L"computers":L"groups";
            emitted=&placeholder;
        }
        if(!ah_output_selected(graph,emitted)||!ah_output_dataset(emitted))continue;
        ah_buffer json(limit,4096);
        if(!ah_serialize_output_object(graph,emitted,json)||!ah_active_combined_output->capture_row(ah_output_dataset(emitted),emitted->id,false,ah_eq(emitted->raw_sid,"S-1-5-9"),json))return false;
        ah_observe_object_completed();
    }
    return ah_active_combined_output->capture_calls(graph.directory)&&!graph.arena.failed;
}

static bool ah_export_dataset(ah_graph &graph,ah_zip &zip,ah_buffer &json,const char *base,const char *timestamp) {
    if(ah_active_combined_output)return ah_active_combined_output->capture(base,json);
    return ah_write_dataset(graph.arena,zip,json,base,timestamp);
}
static void ah_csv_cell(ah_buffer &csv,const char *value) {
    if(!value)return;
    bool quote=false;for(const char *p=value;*p;++p)if(*p==','||*p=='"')quote=true;
    if(quote)AH_TEXT(&csv,"\"");
    for(const char *p=value;*p;++p) {
        if(*p=='\t'||*p=='\r'||*p=='\n')continue;
        ah_append(&csv,p,1);if(*p=='"')AH_TEXT(&csv,"\"");
    }
    if(quote)AH_TEXT(&csv,"\"");
}
static bool ah_export_call_status(ah_graph &graph,size_t limit,const char *timestamp) {
    if(!ah_track_computer_calls||!graph.directory.call_status)return true;
    if(ah_active_combined_output)return ah_active_combined_output->capture_calls(graph.directory);
    ah_buffer csv(limit);AH_TEXT(&csv,"ComputerName,Task,Status,ObjectID\r\n");
    for(ah_call_status *row=graph.directory.call_status;row;row=row->next) {
        ah_csv_cell(csv,row->computer);AH_TEXT(&csv,", ");ah_csv_cell(csv,row->task);AH_TEXT(&csv,", ");
        ah_csv_cell(csv,row->status);AH_TEXT(&csv,", ");ah_csv_cell(csv,row->object_id);AH_TEXT(&csv,"\r\n");
    }
    char *name=ah_output_name(graph.arena,"compstatus","csv",timestamp);
    if(!name||csv.failed||csv.length>0x7fffffffU)return false;
    AxDownloadMemory(name,csv.data,static_cast<int>(csv.length));return !graph.arena.failed;
}

static bool ah_host_collection_selected(ah_graph &graph,const ah_object *object) {

    if(!ah_eq(object->kind,"Computer")||object->auxiliary_only||!object->dn||!*object->dn)return false;
    return graph.computer_selected(object);
}

static bool ah_export(ah_directory &directory, const ah_profile *profile, const wchar_t *base, char *filename, size_t limit, const wchar_t *dc, int collection, const char *forest_root_id) {
    if(profile->security_descriptors&&!ah_active_combined_output) {
        ah_combined_output output(limit,collection);ah_combined_scope scope(output);
        return ah_export(directory,profile,base,filename,limit,dc,collection,forest_root_id)&&output.finish(filename,profile,output.primary_domain());
    }
    ah_current_dc = dc;
    ah_collection = collection;
    ah_forest_root_id = forest_root_id;
    if (profile->security_descriptors && !ah_ad_wellknown(directory)) return false;
    ah_graph graph(directory, profile->security_descriptors != 0);
    if (!graph.init(base)) { BeaconPrintf(CALLBACK_ERROR, "Cannot resolve graph identifiers or domain root"); return false; }
    if(ah_active_combined_output&&!ah_active_combined_output->discover_domain(graph.domain,graph.root->id))return false;
    if (graph.ad && !graph.select_computers(ah_stealth || ah_computer_file_mode ? "" : ah_computer_targets)) return false;
    ah_host_pool hosts(graph,limit);
    if(graph.ad&&(ah_computer_collection(collection)||(collection&AH_LDAP_SERVICES))&&!hosts.collect(dc,collection,ah_threads,ah_host_collection_selected)) {
        BeaconPrintf(CALLBACK_ERROR,"AdaptiHound: host collection failed (worker status %u)",hosts.error());return false;
    }
    if (graph.ad) return ah_export_ad_objects(graph,limit,dc);
    if (!*filename) {
        filename = ah_default_filename(graph.arena, profile, graph.domain);
        if (!filename) return false;
    }
    char timestamp[16];if(!ah_output_timestamp(timestamp))return false;
    filename=ah_output_name(graph.arena,filename,"zip",timestamp);
    if(!filename)return false;
    ah_zip zip(limit,ah_zip_password);unsigned int exported=0;
    if (graph.ad) {
        static const wchar_t *types[] = {L"users", L"computers", L"groups", L"domains", L"ous", L"gpos", L"containers"};
        static const char *names[] = {"users", "computers", "groups", "domains", "ous", "gpos", "containers"};
        for (unsigned int i = 0; i < 7; ++i) {
            if (!ah_dataset_has_rows(graph,types[i])) continue;
            ah_buffer json(limit);
            if (!ah_ad_file(graph, json, types[i], names[i]) || !ah_export_dataset(graph,zip,json,names[i],timestamp)) return false;
            ++exported;
        }
        static const wchar_t *adcs_types[] = {L"rootcas", L"aiacas", L"enterprisecas", L"ntauthstores", L"certtemplates", L"issuancepolicies"};
        static const char *adcs_names[] = {"rootcas", "aiacas", "enterprisecas", "ntauthstores", "certtemplates", "issuancepolicies"};
        for (unsigned int i = 0; i < 6; ++i) {
            if (!ah_dataset_has_rows(graph,adcs_types[i])) continue;
            ah_buffer json(limit);
            if (!ah_adcs_file(graph, json, adcs_types[i], adcs_names[i], collection) || !ah_export_dataset(graph,zip,json,adcs_names[i],timestamp)) return false;
            ++exported;
        }
        static const wchar_t *site_types[] = {L"sites", L"siteservers", L"sitesubnets"};
        static const char *site_names[] = {"sites", "siteservers", "sitesubnets"};
        for (unsigned int i = 0; i < 3; ++i) {
            if (!ah_dataset_has_rows(graph,site_types[i])) continue;
            ah_buffer json(limit);
            if (!ah_site_file(graph, json, site_types[i], site_names[i]) || !ah_export_dataset(graph,zip,json,site_names[i],timestamp)) return false;
            ++exported;
        }
    } else {
        return false;
    }
    if(!ah_export_call_status(graph,limit,timestamp)||directory.arena.failed)return false;
    if(ah_active_combined_output)return ah_active_combined_output->valid();
    if(!exported) { BeaconPrintf(CALLBACK_OUTPUT,"AdaptiHound: no selected objects; no archive produced");return true; }
    if(ah_no_zip){BeaconPrintf(CALLBACK_OUTPUT,"AdaptiHound: %u JSON files ready in Downloads",exported);return true;}
    return zip.download(filename);
}
