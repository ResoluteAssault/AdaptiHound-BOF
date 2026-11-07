#pragma once
#include "producer_contract.hpp"

struct ah_stealth_path final {
    const char *name;
    size_t length;
    uint64_t hash;
    ah_stealth_path *bucket_next, *next;
};

class ah_stealth_paths final {
    ah_arena &arena;
    ah_stealth_path **buckets = nullptr;
    size_t capacity = 0, count = 0;
    ah_stealth_path *last = nullptr;
    bool grow() {
        if (capacity > SIZE_MAX / 2) { arena.failed = true; return false; }
        size_t size = capacity ? capacity * 2 : 64;
        if (size > SIZE_MAX / sizeof(*buckets)) { arena.failed = true; return false; }
        auto **replacement = ah_alloc<ah_stealth_path *>(size * sizeof(*buckets));
        if (!replacement) { arena.failed = true; return false; }
        for (ah_stealth_path *path = first; path; path = path->next) {
            size_t bucket = static_cast<size_t>(path->hash) & (size - 1);
            path->bucket_next = replacement[bucket]; replacement[bucket] = path;
        }
        ah_free(buckets); buckets = replacement; capacity = size; return true;
    }
public:
    ah_stealth_path *first = nullptr;
    explicit ah_stealth_paths(ah_arena &owner) : arena(owner) {}
    ~ah_stealth_paths() { ah_free(buckets); }
    ah_stealth_paths(const ah_stealth_paths &) = delete;
    ah_stealth_paths &operator=(const ah_stealth_paths &) = delete;
    bool add(const char *path, size_t length) {
        uint64_t hash = 1469598103934665603ULL;
        for (size_t i = 0; i < length; ++i) { hash ^= static_cast<unsigned char>(path[i]); hash *= 1099511628211ULL; }
        if (capacity) for (auto *entry = buckets[static_cast<size_t>(hash) & (capacity - 1)]; entry; entry = entry->bucket_next) {
            if (entry->hash != hash || entry->length != length) continue;
            size_t i = 0; while (i < length && entry->name[i] == path[i]) ++i;
            if (i == length) return true;
        }
        if (!capacity || count >= capacity - capacity / 4) if (!grow()) return false;
        auto *entry = arena.make<ah_stealth_path>();
        if (!entry) return false;
        entry->name = arena.copy(path, length);
        if (!entry->name) return false;
        entry->length = length; entry->hash = hash; entry->next = nullptr;
        const size_t bucket = static_cast<size_t>(hash) & (capacity - 1);
        entry->bucket_next = buckets[bucket]; buckets[bucket] = entry;
        if (last) last->next = entry; else first = entry;
        last = entry; ++count; return true;
    }
    bool add_value(const char *value) {

        const char *part = value;
        for (unsigned int split = 0; split < 2; ++split) {
            while (*part && *part != '\\') ++part;
            if (!*part) return true;
            ++part;
        }
        const char *end = part; while (*end && *end != '\\') ++end;
        return add(part, static_cast<size_t>(end - part));
    }
};

struct ah_stealth_domain final {
    const char *name, *sid;
    ah_stealth_domain *next;
};

class ah_stealth_domains final {
    ah_arena &arena;
    ah_stealth_domain *last = nullptr;
public:
    ah_stealth_domain *first = nullptr;
    explicit ah_stealth_domains(ah_arena &owner) : arena(owner) {}
    bool add(const char *name, const char *sid = nullptr) {
        if (!name || !*name) return true;
        for (auto *entry = first; entry; entry = entry->next) {
            if ((sid && entry->sid && ah_eq(sid, entry->sid)) || ah_eq(name, entry->name)) {
                if (!entry->sid && sid) entry->sid = arena.copy(sid);
                return !arena.failed;
            }
        }
        auto *entry = arena.make<ah_stealth_domain>();
        if (!entry) return false;
        entry->name = arena.copy(name); entry->sid = sid ? arena.copy(sid) : nullptr; entry->next = nullptr;
        if (arena.failed) return false;
        if (last) last->next = entry; else first = entry;
        last = entry; return true;
    }
};

struct ah_stealth_binding final {
    LDAP *handle = nullptr;
    wchar_t *base = nullptr;
    bool owns_handle = false;
    ~ah_stealth_binding() { if (owns_handle && handle) ah_close_directory(handle); ah_free(base); }
    bool open(LDAP *primary, const wchar_t *domain_base, const char *primary_domain,
              const char *domain, const ah_options &options) {

        if (ah_eq(primary_domain, domain) || (options.server && *options.server)) {
            handle = primary;
            size_t length = ah_wlen(domain_base);
            if (length >= SIZE_MAX / sizeof(wchar_t)) return false;
            base = ah_alloc<wchar_t>((length + 1) * sizeof(wchar_t));
            if (base) for (size_t i = 0; i <= length; ++i) base[i] = domain_base[i];
            return base != nullptr;
        }
        wchar_t *wide = ah_wide(domain); PDOMAIN_CONTROLLER_INFOW dc = nullptr;
        ULONG status = wide ? NETAPI32$DsGetDcNameW(nullptr, wide, nullptr, nullptr,
            DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dc) : ERROR_NOT_ENOUGH_MEMORY;
        ah_free(wide);
        if (status == ERROR_SUCCESS && dc) {
            const wchar_t *host = dc->DomainControllerName;
            if (host && host[0] == '\\' && host[1] == '\\') host += 2;
            if (host) handle = ah_open_directory(host, options, false, 30, status);
            owns_handle = handle != nullptr;
        }
        if (dc) NETAPI32$NetApiBufferFree(dc);
        if (handle) base = ah_root(handle, L"defaultNamingContext");
        return handle && base;
    }
};

static bool ah_stealth_collect_paths(ah_stealth_paths &paths, LDAP *ld, wchar_t *base, unsigned int pages) {
    ah_directory scratch(0, 4096);
    static const wchar_t *const attributes[] = {L"homedirectory", L"scriptpath", L"profilepath", nullptr};
    static const char *const names[] = {"homedirectory", "scriptpath", "profilepath"};
    const ah_query query = {L"stealthpaths", L"",
        L"(&(samaccounttype=805306369)(|(homedirectory=*)(scriptpath=*)(profilepath=*)))", LDAP_SCOPE_SUBTREE, 1};

    ah_dataset(scratch, ld, &query, base, attributes, 0, pages, false, false, false, true);
    for (ah_object *object = scratch.objects; object && !scratch.arena.failed; object = object->next) {
        for (unsigned int index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {

            ah_value *value = object->values(names[index]);
            if (value && !paths.add_value(value->data)) return false;
        }
    }
    return !scratch.arena.failed;
}

static bool ah_stealth_collect_trust_domains(ah_stealth_domains &domains, LDAP *ld, wchar_t *base, unsigned int pages) {
    ah_directory scratch(0, 4096);
    static const wchar_t *const attributes[] = {L"trustattributes", L"securityidentifier", L"trustdirection", L"trusttype", L"cn", nullptr};
    const ah_query query = {L"stealthtrusts", L"", L"(objectclass=trusteddomain)", LDAP_SCOPE_SUBTREE, 1};
    ah_dataset(scratch, ld, &query, base, attributes, 0, pages, false, false, false, true);
    for (ah_object *object = scratch.objects; object && !scratch.arena.failed; object = object->next) {
        auto *binary = object->values("securityIdentifier");
        if (!binary || !object->values("trustDirection") || !object->values("trustAttributes")) continue;
        const char *sid = ah_sid(scratch.arena, reinterpret_cast<unsigned char *>(binary->data), binary->size);
        if (sid && !domains.add(object->text("cn"), sid)) return false;
    }
    return !scratch.arena.failed;
}

static bool ah_stealth_forest_domains(ah_stealth_domains &domains, ah_arena &arena, const wchar_t *server) {
    PDS_DOMAIN_TRUSTSW trusts = nullptr; ULONG count = 0;
    ULONG status = NETAPI32$DsEnumerateDomainTrustsW(const_cast<wchar_t *>(server), DS_DOMAIN_IN_FOREST, &trusts, &count);
    bool complete = true;
    if (status == ERROR_SUCCESS && trusts) for (ULONG i = 0; i < count && complete; ++i) {
        if (!trusts[i].DnsDomainName || !trusts[i].DomainSid) continue;
        auto *bytes = static_cast<const unsigned char *>(trusts[i].DomainSid);
        const char *sid = bytes[0] == 1 && bytes[1] <= 15 ? ah_sid(arena, bytes, 8 + 4 * bytes[1]) : nullptr;
        if (sid) complete = domains.add(arena.utf8(trusts[i].DnsDomainName), sid);
    }
    if (trusts) NETAPI32$NetApiBufferFree(trusts);
    return complete && !arena.failed;
}

static bool ah_stealth_discover(ah_directory &output, LDAP *primary,
                               const wchar_t *server, const wchar_t *domain_base,
                               const ah_options &options, const ah_profile *profile,
                               int methods, unsigned int pages) {
    if (!options.stealth || !profile->security_descriptors) return true;
    const uint64_t failures = ah_memory_active_budget ? ah_memory_active_budget->allocation_failures() : 0;
    ah_directory scratch(0, 4096); ah_graph graph(scratch, true);
    ah_object root = {}; root.dn = scratch.arena.utf8(domain_base);
    graph.domain = const_cast<char *>(graph.object_domain(&root)); graph.root = &root;
    if (!graph.domain || scratch.arena.failed) { output.arena.failed = true; return false; }
    ah_stealth_domains domains(scratch.arena); ah_stealth_paths paths(scratch.arena);
    bool complete = true;

    if (options.recurse_domains) {
        char *initial = ah_discover_domain("");
        complete = !initial || domains.add(initial);
        ah_free(initial);
    } else {
        complete = domains.add(graph.domain);
        if (complete && options.search_forest) complete = ah_stealth_forest_domains(domains, scratch.arena, server);
    }
    for (auto *domain = domains.first; domain && complete; domain = domain->next) {
        ah_stealth_binding binding;
        if (!binding.open(primary, domain_base, graph.domain, domain->name, options)) continue;
        if (options.recurse_domains) complete = ah_stealth_collect_trust_domains(domains, binding.handle, binding.base, pages);
        if (complete) complete = ah_stealth_collect_paths(paths, binding.handle, binding.base, pages);
    }
    ah_producer_parameters parameters = {};
    if (complete) complete = ah_stealth_parameters(scratch.arena, methods, nullptr, false, parameters);
    for (auto *path = paths.first; path && complete; path = path->next) {

        const char *host = path->name, *end = host + path->length;
        for (const char *p = host; p < end; ++p) if (*p == '/') {
            host = p + 1; end = host;
            while (*end && *end != '/' && *end != ':') ++end;
            break;
        }
        while (end > host && end[-1] == '$') --end;
        ah_directory resolution(0, 4096); ah_graph resolver(resolution, true);
        resolver.domain = graph.domain; resolver.root = &root;
        char *name = resolution.arena.copy(host, static_cast<size_t>(end - host));
        if (!name) { complete = false; break; }
        const char *sid = *name ? ah_target_host_sid(resolver, name) : nullptr;
        if (resolution.arena.failed) { complete = false; break; }
        if (!sid) continue;
        if (ah_track_computer_calls) {
            ah_graph tracked(output, true);
            ah_track_resolved_call(tracked, path->name, sid, "StealthProducer - FindPathTargetSids", "Success");
            if (output.arena.failed) { complete = false; break; }
        }
        if (!ah_prefix(sid, "S-1-5")) continue;
        unsigned char binary[68]; size_t length = 0;
        if (!ah_gpo_sid_bytes(sid, binary, length)) continue;
        ah_buffer filter(1024); AH_TEXT(&filter, "(objectsid=");
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < length; ++i) {
            char escaped[] = {'\\', hex[binary[i] >> 4], hex[binary[i] & 15]}; ah_append(&filter, escaped, sizeof(escaped));
        }
        AH_TEXT(&filter, ")\0"); wchar_t *wide = filter.failed ? nullptr : ah_wide(filter.data);
        if (!wide) { complete = false; break; }
        LDAPMessage *result = nullptr; struct l_timeval timeout = {ah_ldap_query_timeout_seconds, 0};

        ah_ldap_search_retry(primary, const_cast<wchar_t *>(domain_base), LDAP_SCOPE_SUBTREE,
            wide, const_cast<wchar_t **>(parameters.attributes), 0, nullptr, nullptr, &timeout, 1, &result);
        if (result) WLDAP32$ldap_msgfree(result);
        ah_free(wide);
    }
    if (complete && !options.exclude_dcs) {
        ah_directory controllers(0, 4096);
        const ah_query query = {L"stealthcontrollers", L"", L"(userAccountControl:1.2.840.113556.1.4.803:=8192)", LDAP_SCOPE_SUBTREE, 1};
        ah_dataset(controllers, primary, &query, const_cast<wchar_t *>(domain_base), parameters.attributes, 0, pages, false, false, false, true);
        complete = !controllers.arena.failed;
    }
    const bool exhausted = ah_memory_active_budget && ah_memory_active_budget->allocation_failures() != failures;
    if (!complete || scratch.arena.failed || exhausted || output.arena.failed) { output.arena.failed = true; return false; }
    return true;
}
