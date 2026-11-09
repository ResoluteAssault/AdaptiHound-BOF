#pragma once
#include "batch_support.hpp"
#include "../graph/batch_output.hpp"

// A bounded collection uses a disposable lookup cache, never a disk cache. Cache
// values may be borrowed by a graph, so recycling happens only between batches.
class ah_batch_cache final {
    ah_cache_data data;
    ah_cache_data *previous;
public:
    explicit ah_batch_cache(size_t limit) : data(limit), previous(ah_current_cache) { ah_current_cache = &data; }
    ~ah_batch_cache() { ah_current_cache = previous; }
    bool next() {
        if (data.exhausted || data.arena.allocated_bytes() > data.limit() / 2) data.reset();
        return data.valid();
    }
};

static bool ah_bounded_requested(const ah_options &options, const ah_profile *profile) {
    return profile->security_descriptors && (options.mib > 0 || ah_memory_auto(options)) && !options.stealth &&
        !options.search_forest && !options.recurse_domains && !(options.runtime_flags & 128) &&
        (!options.computers || !*options.computers);
}

static bool ah_batch_remember_dc(ah_directory &identities, const ah_object &source) {
    if (source.auxiliary_only || !ah_weq(source.type, L"computers") ||
        !(ah_unsigned(source.text("userAccountControl")) & 0x2000)) return true;
    if (ah_batch_find_dn(identities, source.dn)) return true;
    ah_object *copy = identities.add(L"computers", source.dn);
    if (!copy) return false;
    const char *attributes[] = {"objectSid", "objectGUID", "objectClass", "sAMAccountType",
        "userAccountControl", "dNSHostName", "sAMAccountName", "name", "cn", nullptr};
    for (const char **name = attributes; *name; ++name)
        for (ah_value *value = source.values(*name); value; value = value->next)
            if (!identities.value(identities.attribute(copy, *name), value->data, value->size)) return false;
    return !identities.arena.failed;
}

struct ah_batch_collection final {
    const ah_options &options;
    const ah_profile *profile;
    LDAP *ld;
    const wchar_t *base, *server;
    const char *forest_id;
    ah_directory &support, &controllers;
    ah_archive_parts &parts;
    ah_batch_output &output;
    ah_batch_cache &cache;
    size_t maximum, batch_target;
    unsigned int pages;

    bool query(const ah_query &query, const wchar_t *context, const wchar_t *const *attrs,
        int sd, bool main_producer, const wchar_t *filter) {
        ah_ldap_cursor cursor(ld, query, context, attrs, sd ? &ah_ad_security_control : nullptr, pages, filter);
        LDAPMessage *entry = cursor.next();
        while (entry) {
            if (!cache.next()) return false;
            {
                ah_directory batch(maximum, 4096);
                if (!ah_batch_clone_support(batch, support)) return false;
                ah_arena lookup_storage(0, 4096);
                ah_index existing;
                if (batch.count > SIZE_MAX - 128 || !existing.init(lookup_storage, batch.count + 128)) return false;
                for (ah_object *object = batch.objects; object; object = object->next) existing.put(object->dn, object);
                unsigned int consumed = 0;
                do {
                    // The only producer/support overlaps are the domain root and
                    // AdminSDHolder. Explicitly promote them after a selected entry.
                    wchar_t *dn = WLDAP32$ldap_get_dnW(cursor.connection(), entry);
                    const char *name = dn ? batch.arena.utf8(dn) : nullptr;
                    ah_object *old = name ? existing.find(name) : nullptr;
                    if (dn) WLDAP32$ldap_memfreeW(dn);
                    if (!name || !cursor.append(batch, main_producer, false, &existing, ah_ad_entry_policy)) return false;
                    if (old && !(main_producer && ah_ad_entry_policy.skip && ah_ad_entry_policy.skip(name))) old->auxiliary_only = false;
                    ++consumed;
                    entry = cursor.next();
                } while (entry && consumed < 128 && batch.arena.allocated_bytes() < batch_target);
                if (batch.arena.failed || lookup_storage.failed) return false;
                for (ah_object *object = batch.objects; object; object = object->next)
                    if (!ah_batch_remember_dc(controllers, *object)) return false;
                if (!ah_batch_gpo_dependencies(batch, cursor.connection(), pages, options.collection)) return false;
                if (!output.export_batch(batch, profile, base, server, options.collection, forest_id)) return false;
            }
            // The previous graph, native worker contexts, JSON rows and their
            // derived data have all been destroyed before another batch starts.
            ah_drain_observability();
        }
        if (!cursor.complete()) {
            BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: bounded LDAP query incomplete (%ls, LDAP %u)", query.type, cursor.status());
            return false;
        }
        return parts.valid();
    }

    bool dataset(const ah_query &query, const wchar_t *context, const wchar_t *const *attrs,
        int sd, bool partition) {
        const bool has_custom = *ah_ldap_filter || ah_ldap_filter_present;
        wchar_t *custom = has_custom ? ah_ldap_filter_normalize(ah_ldap_filter) : nullptr;
        if (has_custom && !custom) return false;
        wchar_t *combined = nullptr;
        const wchar_t *selected = query.filter;
        if (custom) {
            const size_t length = ah_wlen(query.filter) + ah_wlen(custom) + 4;
            combined = ah_alloc<wchar_t>(length * sizeof(wchar_t));
            if (combined) MSVCRT$_snwprintf(combined, length, L"(&%ls%ls)", query.filter, custom);
            ah_free(custom);
            if (!combined) return false;
            selected = combined;
        }
        bool complete = true;
        if (partition && ah_partition_queries) {
            const size_t length = ah_wlen(selected) + 32;
            wchar_t *part = ah_alloc<wchar_t>(length * sizeof(wchar_t));
            if (!part) complete = false;
            else for (unsigned int i = 0; i < 256 && complete; ++i) {
                MSVCRT$_snwprintf(part, length, L"(&%ls(objectGUID=\\%02x*))", selected, i);
                complete = this->query(query, context, attrs, sd, true, part);
            }
            ah_free(part);
        } else complete = this->query(query, context, attrs, sd, true, selected);
        ah_free(combined);
        return complete;
    }

    bool profile_query(const ah_query &original, const wchar_t *context, bool configuration) {
        if (ah_weq(original.type, L"trusts") || ah_weq(original.type, L"directoryservices") ||
            ah_weq(original.type, L"crossrefs") || !ah_query_enabled(original.type, options.collection)) return true;
        ah_query selected_query = original;
        if (const wchar_t *filter = ah_query_filter(original.type, options.collection)) selected_query.filter = filter;
        const wchar_t *all[] = {L"*", nullptr}, *selected[256];
        unsigned int count = 0;
        for (const wchar_t *const *attribute = profile->attributes; *attribute; ++attribute) {
            if (!ah_query_attribute_enabled(*attribute, options.collection, configuration)) continue;
            if (count + 1 >= sizeof(selected) / sizeof(selected[0])) return false;
            selected[count++] = *attribute;
        }
        selected[count] = nullptr;
        const wchar_t *const *attrs = ah_collect_all_properties && !configuration ? all : selected;
        const int sd = configuration ? (options.collection & (AH_ACL | AH_CERT_SERVICES | AH_SITE)) : (options.collection & AH_ACL);
        if (!dataset(selected_query, context, attrs, sd, !configuration)) return false;
        if (!configuration && ah_weq(original.type, L"computers") && !ah_broad_collection(options.collection) &&
            ah_computer_collection(options.collection) && (options.collection & (AH_DC_REGISTRY | AH_LDAP_SERVICES))) {
            // Preserve the legacy producer's supplemental DC records, including
            // its multiplicity when a DC also matched the preceding host query.
            selected_query.filter = L"(&(sAMAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))";
            return dataset(selected_query, context, attrs, sd, true);
        }
        return true;
    }
};

static bool ah_collect_bounded(const ah_options &options, const ah_profile *profile, LDAP *ld,
    const wchar_t *server, wchar_t *base) {
    const size_t maximum = ah_memory_limit(options.mib);
    const size_t workspace = ah_memory_workspace(options);
    ah_directory support(maximum, 4096), controllers(maximum, 4096);
    wchar_t *domain_base = ah_root(ld, L"defaultNamingContext");
    wchar_t *configuration = ah_root(ld, L"configurationNamingContext");
    const char *forest_id = nullptr;
    bool ready = domain_base && configuration;
    if (ready) ready = ah_auxiliary_object(support, ld, L"domains", domain_base, profile->attributes,
        (options.collection & AH_ACL) != 0, 1) != 0;
    if (ready && (options.collection & AH_ACL)) {
        const wchar_t *prefix = L"CN=AdminSDHolder,CN=System,";
        const size_t length = ah_wlen(prefix) + ah_wlen(domain_base) + 1;
        wchar_t *admin = ah_alloc<wchar_t>(length * sizeof(wchar_t));
        if (admin) {
            MSVCRT$_snwprintf(admin, length, L"%ls%ls", prefix, domain_base);
            ready = ah_auxiliary_object(support, ld, L"containers", admin, profile->attributes, 1, 1) != 0;
        } else ready = false;
        ah_free(admin);
    }
    if (ready && (options.collection & AH_TRUSTS)) {
        const wchar_t *attrs[] = {L"securityIdentifier", L"trustDirection", L"trustType", L"trustAttributes", L"cn", nullptr};
        const ah_query query = {L"trusts", L"", L"(objectClass=trustedDomain)", LDAP_SCOPE_SUBTREE, 0};
        ready = ah_dataset(support, ld, &query, domain_base, attrs, 0, 32, false, false, true, true) != 0;
    }
    for (unsigned int i = 0; ready && i < profile->query_count; ++i) {
        const ah_query &query = profile->queries[i];
        if ((ah_weq(query.type, L"directoryservices") || ah_weq(query.type, L"crossrefs")) && ah_query_enabled(query.type, options.collection))
            ready = ah_profile_dataset(support, ld, profile, query, configuration, options.collection, true, 32) != 0;
    }
    if (ready && (options.collection & (AH_ACL | AH_CERT_SERVICES))) {
        wchar_t *schema = ah_root(ld, L"schemaNamingContext");
        const wchar_t *attrs[] = {L"lDAPDisplayName", L"schemaIDGUID", nullptr};
        const ah_query query = {L"schema", L"", L"(&(objectClass=attributeSchema)(|(lDAPDisplayName=ms-mcs-admpwd)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword)))", LDAP_SCOPE_SUBTREE, 0};
        ready = schema && ah_dataset(support, ld, &query, schema, attrs, 0, 8);
        ah_free(schema);
    }
    if (ready) {
        wchar_t *forest = ah_root(ld, L"rootDomainNamingContext");
        if (forest) {
            ah_object *metadata = support.add(L"forestmetadata", "");
            char *context = support.arena.utf8(forest);
            ready = metadata && context && support.value(support.attribute(metadata, "nCName"), context, ah_len(context));
            if (ready) forest_id = ah_resolve_forest_sid(support, ld, server, forest, context, base, options, nullptr, nullptr, nullptr);
            ah_free(forest);
        }
    }
    bool success = false;
    if (ready && !support.arena.failed) {
        ah_graph names(support, true);
        const char *domain = names.object_domain(support.objects);
        // Leave room for the directory, lookup cache, host results, one complete
        // JSON record and compression. The global allocator enforces the ceiling.
        size_t target = workspace / 8;
        if (target > 8 * 1024 * 1024) target = 8 * 1024 * 1024;
        const size_t download_limit = static_cast<size_t>(INT32_MAX) - 1024 * 1024;
        size_t single_row_limit = ah_memory_auto(options) ? (maximum ? maximum : download_limit) : maximum / 4;
        if (single_row_limit > download_limit) single_row_limit = download_limit;
        ah_archive_parts parts(maximum, target, options.collection, options.output, profile, domain,
            nullptr, nullptr, single_row_limit);
        ah_batch_output output(parts, maximum);
        ah_batch_cache cache(workspace / 8);
        unsigned int pages = static_cast<unsigned int>(options.pages);
        if (pages > 32) pages = 32;
        ah_batch_collection collection{options, profile, ld, base, server, forest_id, support, controllers,
            parts, output, cache, maximum, workspace / 16, pages};
        bool complete = parts.valid() && cache.next();
        bool configuration_query = false;
        const int requested_threads = ah_threads;
        const size_t allowed_threads = workspace / (8 * 1024 * 1024);
        if (static_cast<size_t>(ah_threads) > allowed_threads) ah_threads = allowed_threads ? static_cast<int>(allowed_threads) : 1;
        if (maximum)
            ah_log_telemetry("AdaptiHound: bounded AD collection, %llu-byte BOF heap ceiling, %llu-byte ZIP part target; Downloads are delivered after the task returns",
                static_cast<unsigned long long>(maximum), static_cast<unsigned long long>(target));
        else
            ah_log_telemetry("AdaptiHound: economical AD collection, no user hard ceiling, %llu-byte ZIP part target; Downloads are delivered after the task returns",
                static_cast<unsigned long long>(target));
        for (unsigned int i = 0; complete && i < profile->query_count; ++i) {
            const ah_query &query = profile->queries[i];
            if (ah_weq(query.type, L"configuration")) configuration_query = true;
            complete = collection.profile_query(query, configuration_query ? configuration : base, configuration_query);
        }
        if (complete) {
            ah_directory final_support(maximum, 4096);
            complete = ah_batch_clone_support(final_support, support);
            for (ah_object *object = controllers.objects; complete && object; object = object->next)
                complete = ah_batch_clone_object(final_support, *object, false) != nullptr;
            if (complete && cache.next()) complete = output.export_builtins(final_support, profile, base, server, options.collection, forest_id);
            else complete = false;
        }
        ah_threads = requested_threads;
        success = parts.finish(complete && output.valid());
        if (ah_telemetry_enabled)
            BeaconPrintf(success ? CALLBACK_OUTPUT : CALLBACK_ERROR, "AdaptiHound: %llu ZIP/JSON parts, %llu records; collection %s%s%s",
                static_cast<unsigned long long>(parts.parts()), static_cast<unsigned long long>(parts.records()),
                success ? "complete" : "incomplete", parts.failure_reason() ? ": " : "", parts.failure_reason() ? parts.failure_reason() : "");
        else
            BeaconPrintf(success ? CALLBACK_OUTPUT : CALLBACK_ERROR, "AdaptiHound: collection %s; %llu parts prepared for Downloads%s%s",
                success ? "complete" : "incomplete", static_cast<unsigned long long>(parts.parts()),
                parts.failure_reason() ? ": " : "", parts.failure_reason() ? parts.failure_reason() : "");
    } else BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: bounded collection could not load domain support metadata; no archive sent");
    ah_free(domain_base); ah_free(configuration);
    return success;
}
