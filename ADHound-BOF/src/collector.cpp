#include "../../common/core/collector.h"
#include "core/platform.hpp"
#include "../../common/core/imports.hpp"
#include "core/imports.hpp"
#include "../../common/core/buffer.hpp"
#include "core/directory.hpp"
#include "core/collection.hpp"
#include "../../common/core/observability.hpp"
#include "../../common/ldap/ldap_query.hpp"
#include "../../common/ldap/ldap_entry_policy.hpp"
#include "collection/ldap_entries.hpp"
#include "../../common/ldap/ldap_collect.hpp"
#include "collection/ldap_controls.hpp"
#include "collection/dataset.hpp"
#include "../../common/ldap/ldap_connection.hpp"
#include "graph/graph.hpp"
#include "../../common/core/options.hpp"
static char *ah_heap_copy(const char *source) {
    if (!source) return nullptr;
    size_t n = ah_len(source); char *out = ah_alloc(n + 1);
    if (out) for (size_t i = 0; i <= n; ++i) out[i] = source[i];
    return out;
}
static char *ah_domain_base(const char *domain) {
    ah_buffer out(1024); bool first = true;
    for (const char *p = domain; *p;) {
        const char *end = p;
        while (*end && *end != '.') ++end;
        if (end == p) return nullptr;
        for (const char *c = p; c < end; ++c) if (!( (*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9') || *c == '-' )) return nullptr;
        if (!first) { AH_TEXT(&out, ","); }
        first = false; AH_TEXT(&out, "DC="); ah_append(&out, p, static_cast<size_t>(end - p));
        p = *end ? end + 1 : end;
    }
    AH_TEXT(&out, "\0");
    return out.failed ? nullptr : ah_heap_copy(out.data);
}
static char *ah_discover_domain(const char *domain) {
    wchar_t *wide = domain && *domain ? ah_wide(domain) : nullptr;
    PDOMAIN_CONTROLLER_INFOW dc = nullptr;
    ULONG status = NETAPI32$DsGetDcNameW(nullptr, wide, nullptr, nullptr, DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dc);
    ah_free(wide);
    if (status != ERROR_SUCCESS || !dc) return nullptr;
    ah_arena arena(131072); char *name = arena.utf8(dc->DomainName);
    char *result = name ? ah_heap_copy(name) : nullptr;
    NETAPI32$NetApiBufferFree(dc); return result;
}
#include "core/runtime.hpp"
#include "collection/gpo_lookup.hpp"

static void ah_apply_runtime_options(const ah_options &o) {
    ah_skip_registry_loggedon = (o.runtime_flags & 1) != 0;
    ah_partition_queries = (o.runtime_flags & 8) != 0;
    ah_local_admin_session = (o.runtime_flags & 16) != 0;
    ah_extended_sessions = (o.runtime_flags & 32) != 0;
    ah_conservative_probes = (o.runtime_flags & 64) != 0;
    ah_computer_file_mode = (o.runtime_flags & 128) != 0;
    ah_computer_file_path = o.computer_file_path;
    ah_computer_file_text = o.computer_file_text;
    ah_computer_file_inline = (o.option_presence & 32) != 0;
    ah_pretty_print = (o.runtime_flags & 256) != 0;
    ah_no_zip = (o.runtime_flags & 512) != 0;
    ah_random_filenames = (o.runtime_flags & 1024) != 0;
    ah_track_computer_calls = (o.runtime_flags & 2048) != 0;
    ah_ldap_filter = o.ldap_filter;
    ah_ldap_filter_present = *o.ldap_filter || (o.option_presence & 128);
    ah_local_admin_username = o.local_admin_username; ah_local_admin_password = o.local_admin_password;
    ah_override_username = o.override_username; ah_real_dns_name = o.real_dns_name;
    ah_real_dns_name_present = *o.real_dns_name || (o.option_presence & 512);
    ah_throttle = o.throttle; ah_jitter = o.jitter;
    ah_threads=o.threads;
    ah_output_prefix = o.output_prefix; ah_zip_password = o.zip_password;
}
static bool ah_has_directory_dn(ah_directory &data, const char *dn) {
    for (ah_object *o = data.objects; o; o = o->next) if (ah_eq(o->dn,dn)) return true;
    return false;
}
static int ah_auxiliary_object(ah_directory &data, LDAP *ld, const wchar_t *type, wchar_t *dn, const wchar_t *const *attrs, int sd, unsigned int pages) {
    char *name = data.arena.utf8(dn);
    if (!name) return 0;
    if (ah_has_directory_dn(data,name)) return 1;
    const ah_query q = {type,L"",L"(objectClass=*)",LDAP_SCOPE_BASE,1};
    return ah_dataset(data,ld,&q,dn,attrs,sd,pages,false,false,true,true);
}
static int ah_profile_dataset(ah_directory &data, LDAP *ld, const ah_profile *profile, const ah_query &original, wchar_t *base, int methods, bool configuration, unsigned int pages) {
    ah_query query = original;
    if (profile->security_descriptors) {

        if (ah_weq(query.type,L"trusts")) return 1;
        if (!ah_query_enabled(query.type,methods)) return 1;
        const wchar_t *filter = ah_query_filter(query.type,methods); if (filter) query.filter=filter;
    }
    const wchar_t *all[] = {L"*",nullptr};
    const wchar_t *selected[256]; unsigned int count=0;
    for (const wchar_t *const *p=profile->attributes;*p;++p) {
        const bool metadata = ah_weq(query.type,L"crossrefs") || ah_weq(query.type,L"directoryservices");
        if (!profile->security_descriptors || metadata || ah_query_attribute_enabled(*p,methods,configuration)) {
            if (count+1>=sizeof(selected)/sizeof(selected[0])) { data.arena.failed=true;return 0; }
            selected[count++]=*p;
        }
    }
    selected[count]=nullptr;
    const wchar_t *const *attrs = ah_collect_all_properties && !configuration ? all : selected;
    int sd = profile->security_descriptors && (configuration ? (methods & (AH_ACL|AH_CERT_SERVICES|AH_SITE)) : (methods & AH_ACL));
    int complete = ah_dataset(data,ld,&query,base,attrs,sd,pages,profile->security_descriptors!=0,!configuration);
    if (profile->security_descriptors && !configuration && ah_weq(query.type,L"computers") &&
        !ah_broad_collection(methods) && ah_computer_collection(methods) &&
        (methods & (AH_DC_REGISTRY | AH_LDAP_SERVICES)) && !data.arena.failed) {

        query.filter=L"(&(sAMAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))";
        if (!ah_dataset(data,ld,&query,base,attrs,sd,pages,true,true)) complete=0;
    }
    return complete;
}

#include "collection/computer_file.hpp"
#include "collection/stealth_discovery.hpp"

static int ah_stealth_dataset(ah_directory &data,LDAP *ld,wchar_t *base,int methods,bool configuration,unsigned int pages) {
    ah_arena parameters_arena(0,4096);
    ah_producer_parameters parameters={};
    if(!ah_stealth_parameters(parameters_arena,methods,(*ah_ldap_filter||ah_ldap_filter_present)?ah_ldap_filter:nullptr,configuration,parameters)) {
        data.arena.failed=true;return 0;
    }
    if(!parameters.enabled)return 1;
    const ah_query query={configuration?L"stealthconfiguration":L"stealthdefault",L"",parameters.filter,LDAP_SCOPE_SUBTREE,0};

    return ah_dataset(data,ld,&query,base,parameters.attributes,0,pages,false,false);
}

static char *ah_forest_domain_sid(ah_arena &arena, const unsigned char *sid, size_t length) {
    if (!sid || length != 24 || sid[0] != 1 || sid[1] != 4 || sid[2] || sid[3] || sid[4] || sid[5] || sid[6] || sid[7] != 5 || ah_u32(sid + 8) != 21) return nullptr;
    return ah_sid(arena, sid, length);
}
static char *ah_forest_sid_query(ah_arena &arena, LDAP *ld, wchar_t *forest_dn, ULONG &status) {
    wchar_t *attrs[] = {const_cast<wchar_t *>(L"objectSid"), nullptr};
    LDAPMessage *result = nullptr; struct l_timeval timeout = {ah_ldap_query_timeout_seconds, 0};
    status = ah_ldap_search_retry(ld, forest_dn, LDAP_SCOPE_BASE, const_cast<wchar_t *>(L"(objectClass=domainDNS)"), attrs, 0, nullptr, nullptr, &timeout, 1, &result);
    LDAPMessage *entry = status == LDAP_SUCCESS && result ? WLDAP32$ldap_first_entry(ld, result) : nullptr;
    struct berval **values = entry ? WLDAP32$ldap_get_values_lenW(ld, entry, attrs[0]) : nullptr;
    char *sid = values && values[0] ? ah_forest_domain_sid(arena, reinterpret_cast<unsigned char *>(values[0]->bv_val), values[0]->bv_len) : nullptr;
    if (status == LDAP_SUCCESS && !sid) status = values && values[0] ? LDAP_DECODING_ERROR : LDAP_NO_RESULTS_RETURNED;
    if (values) WLDAP32$ldap_value_free_len(values);
    if (result) WLDAP32$ldap_msgfree(result);
    return sid;
}
static char *ah_resolve_forest_sid(ah_directory &directory, LDAP *ld, const wchar_t *server, wchar_t *forest_dn, const char *forest_context, const wchar_t *base, const ah_options &options, wchar_t *user, wchar_t *password, SEC_WINNT_AUTH_IDENTITY_EXW *identity) {
    (void)user; (void)password; (void)identity;
    ULONG status = LDAP_SUCCESS;
    char *sid = ah_forest_sid_query(directory.arena, ld, forest_dn, status);
    if (sid || directory.arena.failed) return sid;

    ah_graph names(directory, true); ah_object forest = {}, current = {};
    forest.dn = const_cast<char *>(forest_context); current.dn = directory.arena.utf8(base);
    const char *forest_domain = names.object_domain(&forest), *current_domain = names.object_domain(&current);
    if (!forest_domain || !*forest_domain || !current_domain || ah_eq(forest_domain, current_domain) || directory.arena.failed) {
        BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: forest root SID unavailable (LDAP %u)", status); return nullptr;
    }

    PDS_DOMAIN_TRUSTSW trusts = nullptr; ULONG count = 0;
    ULONG trust_status = NETAPI32$DsEnumerateDomainTrustsW(const_cast<wchar_t *>(server), DS_DOMAIN_VALID_FLAGS, &trusts, &count);
    if (trust_status == ERROR_SUCCESS && trusts && count <= 4096) {
        for (ULONG i = 0; i < count && !sid && !directory.arena.failed; ++i) {
            if (!trusts[i].DnsDomainName || !trusts[i].DomainSid) continue;
            const char *name = directory.arena.utf8(trusts[i].DnsDomainName);
            if (name && ah_eq(name, forest_domain)) {
                const unsigned char *raw = static_cast<const unsigned char *>(trusts[i].DomainSid);
                if (raw[0] == 1 && raw[1] == 4) sid = ah_forest_domain_sid(directory.arena, raw, 24);
            }
        }
    }
    if (trusts) NETAPI32$NetApiBufferFree(trusts);
    if (sid || directory.arena.failed) return sid;

    wchar_t *domain = ah_wide(forest_domain); PDOMAIN_CONTROLLER_INFOW dc = nullptr;
    ULONG discovery = domain ? NETAPI32$DsGetDcNameW(nullptr, domain, nullptr, nullptr, DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dc) : ERROR_NOT_ENOUGH_MEMORY;
    ah_free(domain);
    LDAP *root_ld = nullptr;
    if (discovery == ERROR_SUCCESS && dc && dc->DomainControllerName && *dc->DomainControllerName) {
        const wchar_t *host = dc->DomainControllerName;
        if (host[0] == '\\' && host[1] == '\\') host += 2;
        root_ld = ah_open_directory(host, options, false, 10, status);
        if (root_ld) sid = ah_forest_sid_query(directory.arena, root_ld, forest_dn, status);
    }
    if (root_ld) ah_close_directory(root_ld);
    if (dc) NETAPI32$NetApiBufferFree(dc);
    if (!sid && !directory.arena.failed) BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: forest root SID unavailable (LDAP %u; root DC discovery %u; topology %u)", status, discovery, trust_status);
    return sid;
}

#include "collection/bounded_collect.hpp"

static bool ah_collect_single(const ah_options &options, const ah_profile *profile) {
    char *server_arg = options.server, *base_arg = options.base, *output = options.output;
    char *user_arg = options.user, *password_arg = options.password;
    int pages = options.pages, mib = options.mib, collection = options.collection;
    ah_apply_runtime_options(options);
    ah_ldap_scope_control=profile->security_descriptors?&ah_ad_scope_control:nullptr;
    ah_collect_all_properties = options.collect_all != 0;
    ah_computer_targets = options.computers ? options.computers : "";
    ah_reserved_attributes = profile->attributes;
    ah_skip_port_scan = options.skip_port_scan != 0; ah_skip_password_age_check = options.skip_password_age_check != 0;
    ah_port_scan_timeout = options.port_scan_timeout;
    ah_stealth = options.stealth != 0; ah_exclude_domain_controllers = options.exclude_dcs != 0;
    if (ah_stealth) {collection = ah_stealth_methods(collection);ah_computer_file_mode=false;}
    ah_collection=collection;
    wchar_t *server = ah_wide(server_arg), *base = ah_wide(base_arg), *user = ah_wide(user_arg), *password = ah_wide(password_arg);
    LDAP *ld = nullptr;
    size_t maximum = ah_memory_limit(mib);
    ah_directory directory(maximum);
    ah_directory_runtime runtime(options);
    int complete = 1;
    bool success = false;
    char *forest_root_id = nullptr;
    unsigned int domain_queries = profile->query_count;
    if (profile->security_descriptors) for (unsigned int i = 0; i < profile->query_count; ++i) if (ah_weq(profile->queries[i].type, L"configuration")) { domain_queries = i; break; }
    ULONG status = 0;
    SEC_WINNT_AUTH_IDENTITY_EXW identity = {};
    if (!server || !base || !user || !password) goto cleanup;
    if (!*server) {
        char *domain=*options.domain?ah_heap_copy(options.domain):ah_discover_domain("");
        ah_free(server);server=domain?ah_wide(domain):nullptr;ah_free(domain);
        if (!server) goto cleanup;
    }
    ld = profile->security_descriptors?ah_open_domain_directory(server, options, false, 30, status):ah_open_directory(server, options, false, 30, status);
    if (!ld) { BeaconPrintf(CALLBACK_ERROR, "LDAP connection/authentication failed: %u", status); goto cleanup; }
    runtime.primary = ld;
    if(auto *record=ah_directory_record(ld)){
        wchar_t *selected=ah_directory_wide_copy(record->server);
        if(!selected)goto cleanup;
        ah_free(server);server=selected;
    }
    if(wchar_t *actual_server=ah_root(ld,L"dNSHostName")){
        ah_note_directory_server(ld,actual_server);ah_free(server);server=actual_server;
    }
    runtime.primary_server = server;
    if (!*base) {
        ah_free(base); base = ah_root(ld, L"defaultNamingContext");
        if(!base&&profile->security_descriptors&&*options.domain){char *text=ah_domain_base(options.domain);base=text?ah_wide(text):nullptr;ah_free(text);}
        if (!base || !*base) { BeaconPrintf(CALLBACK_ERROR, "Cannot select naming context; specify --base-dn"); goto cleanup; }
    }
    if (ah_bounded_requested(options, profile)) {
        success = ah_collect_bounded(options, profile, ld, server, base);
        goto cleanup;
    }
    if(ah_computer_file_mode) {
        wchar_t *context=ah_root(ld,L"defaultNamingContext");
        if(!context)complete=0;
        else {
            if(!ah_auxiliary_object(directory,ld,L"domains",context,profile->attributes,0,(unsigned int)pages))complete=0;
            ah_free(context);
            if(!ah_collect_computer_file(directory,ld,profile,base,collection,(unsigned int)pages))complete=0;
        }
    } else if(profile->security_descriptors&&ah_stealth) {
        if(!ah_stealth_dataset(directory,ld,base,collection,false,(unsigned int)pages))complete=0;
    } else for (unsigned int i = 0; i < domain_queries && !directory.arena.failed; ++i) {
        if (!ah_profile_dataset(directory,ld,profile,profile->queries[i],base,collection,false,(unsigned int)pages)) { complete=0;if(!profile->security_descriptors)break; }
    }
    if (profile->security_descriptors && !directory.arena.failed) {
        wchar_t *domain_base=ah_root(ld,L"defaultNamingContext");
        if (!domain_base) complete=0;
        else {
            if (!ah_auxiliary_object(directory,ld,L"domains",domain_base,profile->attributes,(collection&AH_ACL)!=0,(unsigned int)pages)) complete=0;
            if(ah_stealth&&!ah_stealth_discover(directory,ld,server,domain_base,options,profile,collection,(unsigned int)pages))complete=0;
            if ((collection&AH_ACL)&&!ah_computer_file_mode&&!ah_stealth) {
                const wchar_t *prefix=L"CN=AdminSDHolder,CN=System,";
                size_t length=ah_wlen(prefix)+ah_wlen(domain_base)+1;
                wchar_t *admin=ah_alloc<wchar_t>(length*sizeof(wchar_t));
                if (admin) { MSVCRT$_snwprintf(admin,length,L"%ls%ls",prefix,domain_base); if(!ah_auxiliary_object(directory,ld,L"containers",admin,profile->attributes,1,(unsigned int)pages)) complete=0;ah_free(admin); }
                else directory.arena.failed=true;
            }
            if((collection&AH_TRUSTS)||(options.recurse_domains&&ah_active_combined_output)) {

                const wchar_t *trust_attrs[]={L"securityIdentifier",L"trustDirection",L"trustType",L"trustAttributes",L"cn",nullptr};
                const ah_query trusts={L"trusts",L"",L"(objectClass=trustedDomain)",LDAP_SCOPE_SUBTREE,0};
                if(!ah_dataset(directory,ld,&trusts,domain_base,trust_attrs,0,(unsigned int)pages,false,false,true,true))complete=0;
                if(options.recurse_domains&&ah_active_combined_output&&!ah_active_combined_output->discover_trusts(directory))directory.arena.failed=true;
            }
            if (collection&AH_GPO_LOCAL_GROUP) {
                for (unsigned int i=0;i<domain_queries && !directory.arena.failed;++i) {
                    const ah_query &q=profile->queries[i];
                    if (!ah_weq(q.type,L"gpos") && !ah_weq(q.type,L"computers")) continue;

                    const wchar_t *computer_attributes[]={L"objectSid",nullptr};
                    const wchar_t *const *attributes=ah_stealth&&ah_weq(q.type,L"computers")?computer_attributes:profile->attributes;
                    if(!ah_dataset(directory,ld,&q,domain_base,attributes,0,(unsigned int)pages,false,false,true,true)) complete=0;
                }
            }
            ah_free(domain_base);
        }
    }
    if (profile->security_descriptors && !ah_computer_file_mode && profile->query_count > domain_queries && !directory.arena.failed) {
        wchar_t *configuration = ah_root(ld, L"configurationNamingContext");
        if (!configuration) { BeaconPrintf(CALLBACK_ERROR, "Cannot discover configuration naming context"); complete = 0; }
        else {
            char *context=ah_active_combined_output?directory.arena.utf8(configuration):nullptr;
            const bool collect_configuration=!ah_active_combined_output||(context&&ah_active_combined_output->configuration_once(context));
            if(collect_configuration) {
                if(ah_stealth) {
                    if(!ah_stealth_dataset(directory,ld,configuration,collection,true,(unsigned int)pages))complete=0;
                } else for (unsigned int i = domain_queries; i < profile->query_count && !directory.arena.failed; ++i) {
                    if (!ah_profile_dataset(directory,ld,profile,profile->queries[i],configuration,collection,true,(unsigned int)pages)) complete=0;
                }
            }
            if(ah_active_combined_output&&context) {
                const bool copied=collect_configuration?ah_active_combined_output->remember_support(directory,context):ah_active_combined_output->restore_support(directory,context);
                if(!copied)directory.arena.failed=true;
            }
            ah_free(configuration);
        }
    }
    if (profile->security_descriptors && (collection&(AH_ACL|AH_CERT_SERVICES)) && !directory.arena.failed) {
        wchar_t *schema = ah_root(ld, L"schemaNamingContext");
        const wchar_t *attrs[] = {L"lDAPDisplayName", L"schemaIDGUID", nullptr};
        const ah_query query = {L"schema", L"", L"(&(objectClass=attributeSchema)(|(lDAPDisplayName=ms-mcs-admpwd)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword)))", LDAP_SCOPE_SUBTREE, 0};
        if (!schema) { BeaconPrintf(CALLBACK_ERROR, "Cannot discover schema naming context"); complete = 0; }
        else { if (!ah_dataset(directory, ld, &query, schema, attrs, 0, (unsigned int)pages)) complete = 0; ah_free(schema); }
    }
    if (profile->security_descriptors && !directory.arena.failed) {
        wchar_t *forest_dn = ah_root(ld, L"rootDomainNamingContext");
        if (forest_dn) {
            ah_object *metadata = directory.add(L"forestmetadata", "");
            char *forest_context = directory.arena.utf8(forest_dn);
            if (metadata && forest_context) directory.value(directory.attribute(metadata, "nCName"), forest_context, ah_len(forest_context));
            if (forest_context && !directory.arena.failed) forest_root_id = ah_resolve_forest_sid(directory, ld, server, forest_dn, forest_context, base, options, user, password, &identity);
            ah_free(forest_dn);
        }
    }
    if ((!complete&&!profile->security_descriptors) || directory.arena.failed) {
        if(ah_active_combined_output)ah_active_combined_output->invalidate();
        BeaconPrintf(CALLBACK_ERROR, "LDAP collection incomplete or memory limit reached; no archive sent. Check LDAP errors and --max-mib.");
    }
    else {
        if(!complete)BeaconPrintf(CALLBACK_OUTPUT,"AdaptiHound: LDAP errors occurred; exporting the objects already collected. Review the reported LDAP statuses before using this partial graph.");
        success = ah_export(directory, profile, base, output, maximum, server, collection, forest_root_id);
        if (!success) {
            if(ah_active_combined_output)ah_active_combined_output->invalidate();
            BeaconPrintf(CALLBACK_ERROR, "Graph/ZIP generation failed or memory limit reached; no archive sent.");
        }
    }

cleanup:
    if (ld) ah_close_directory(ld);
    ah_free(server); ah_free(base); ah_free(user);
    if (password) { volatile wchar_t *p = password; size_t n = ah_wlen(password); while (n--) *p++ = 0; ah_free(password); }
    return success;
}

static bool ah_collect_pass(const ah_options &options, const ah_profile *profile) {

    if (ah_bounded_requested(options, profile)) return ah_collect_single(options, profile);

    const bool single=options.stealth||(!options.search_forest&&!options.recurse_domains)||((options.runtime_flags&128)&&!options.stealth);
    if(single) {
        if(!profile->security_descriptors||ah_active_combined_output)return ah_collect_single(options,profile);
        ah_combined_output output(ah_memory_limit(options.mib),options.stealth?ah_stealth_methods(options.collection):options.collection);
        ah_combined_scope scope(output);

        return ah_collect_single(options,profile)&&output.finish(options.output,profile,output.primary_domain());
    }
    if (!profile->security_descriptors) { BeaconPrintf(CALLBACK_ERROR, "Forest/trust collection is an AD option"); return false; }
    char *initial = ah_discover_domain(options.recurse_domains?"":options.domain);
    if (!initial) { BeaconPrintf(CALLBACK_ERROR, "Cannot discover domain; specify --domain"); return false; }
    struct domain_item { char *name,*sid; domain_item *next; };
    ah_arena queue(8 * 1024 * 1024); domain_item *head = nullptr, **tail = &head;
    auto add = [&](const char *name,const char *sid) {
        if (!name || !*name) return true;
        for (domain_item *p = head; p; p = p->next) {
            if(sid&&p->sid&&ah_eq(p->sid,sid))return true;
            if(ah_eq(p->name,name)){if(sid&&!p->sid)p->sid=queue.copy(sid);return !queue.failed;}
        }
        domain_item *item = queue.make<domain_item>(); if (!item) return false;
        item->name = queue.copy(name);item->sid=sid?queue.copy(sid):nullptr;if(!item->name||queue.failed)return false;
        *tail = item; tail = &item->next;return true;
    };
    add(initial,nullptr); ah_free(initial);
    ah_combined_output combined(ah_memory_limit(options.mib),options.stealth?ah_stealth_methods(options.collection):options.collection);
    ah_combined_scope combined_scope(combined);
    bool succeeded = false;
    for (domain_item *item = head; item && !queue.failed; item = item->next) {
        ah_options current = options; current.domain = item->name;
        if (ah_collect_single(current, profile)) succeeded = true;
        if(!combined.valid()||!combined.discovered_domains(add))return false;

        if(options.recurse_domains)continue;
        wchar_t *wide = ah_wide(item->name); PDOMAIN_CONTROLLER_INFOW dc = nullptr;
        ULONG status = NETAPI32$DsGetDcNameW(nullptr, wide, nullptr, nullptr, DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dc);
        ah_free(wide); if (status != ERROR_SUCCESS || !dc) continue;
        PDS_DOMAIN_TRUSTSW trusts = nullptr; ULONG total = 0;
        ULONG flags = DS_DOMAIN_IN_FOREST;
        if (NETAPI32$DsEnumerateDomainTrustsW(dc->DomainControllerName, flags, &trusts, &total) == ERROR_SUCCESS) {
            for (ULONG i = 0; i < total; ++i) {
                if (!trusts[i].DnsDomainName||!trusts[i].DomainSid) continue;
                const unsigned char *raw=static_cast<const unsigned char*>(trusts[i].DomainSid);
                const char *sid=raw[0]==1&&raw[1]<=15?ah_sid(queue,raw,8+4*raw[1]):nullptr;
                if(sid&&!add(queue.utf8(trusts[i].DnsDomainName),sid))break;
            }
        } else BeaconPrintf(CALLBACK_ERROR, "Cannot enumerate trusts for %s", item->name);
        if (trusts) NETAPI32$NetApiBufferFree(trusts);
        NETAPI32$NetApiBufferFree(dc);
    }
    if (queue.failed) BeaconPrintf(CALLBACK_ERROR, "Domain traversal exceeded its memory/domain limit");
    return succeeded && !queue.failed && head && combined.finish(options.output,profile,head->name);
}

static char *ah_loop_filename(const char *output, uint64_t started, unsigned int pass) {
    const char *base = *output ? output : "adaptihound.zip";
    size_t length = ah_len(base);
    if (length < 5 || !ah_eq(base + length - 4, ".zip")) return nullptr;
    ah_buffer name(2048);
    ah_append(&name, base, length - 4); AH_TEXT(&name, "-loop-");
    char tick[32], number[16]; const char *a = ah_decimal(tick + sizeof(tick), started), *b = ah_decimal(number + sizeof(number), pass);
    ah_append(&name, a, ah_len(a)); AH_TEXT(&name, "-"); ah_append(&name, b, ah_len(b)); AH_TEXT(&name, ".zip\0");
    return name.failed ? nullptr : ah_heap_copy(name.data);
}

static ah_zip *ah_loop_zip = nullptr;
static bool ah_loop_capture_archive(char *name,const ah_buffer &body) { return ah_loop_zip&&ah_loop_zip->add_atomic(name,body); }
template <typename Collector>
static void ah_run_loop(const ah_options &options, const ah_profile *profile, Collector collect) {
    if (!options.loop) return;
    int64_t duration_ticks = options.loop_duration_ticks ? options.loop_duration_ticks : static_cast<int64_t>(options.loop_duration ? options.loop_duration : 7200) * 10000000LL;
    int64_t interval_ticks = options.loop_interval_ticks ? options.loop_interval_ticks : static_cast<int64_t>(options.loop_interval ? options.loop_interval : 30) * 10000000LL;
    uint32_t timer_interval = 0;
    if (!ah_timespan_timer_interval(duration_ticks,timer_interval)) {
        BeaconPrintf(CALLBACK_ERROR,"AdaptiHound: LoopDuration is outside System.Timers.Timer's positive Int32-millisecond interval; the initial output is retained");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,"AdaptiHound: waiting 30 seconds before starting loop");
    for(unsigned int i=0;i<30;++i){ah_drain_observability();KERNEL32$Sleep(1000);}
    ULONGLONG started = KERNEL32$GetTickCount64();
    const uint64_t duration_ms = timer_interval, interval_ms = ah_timespan_milliseconds(interval_ticks);
    ULONGLONG deadline = started > UINT64_MAX - duration_ms ? UINT64_MAX : started + duration_ms;
    unsigned int pass = 0;
    ah_options current = options;
    if (options.stealth) current.collection = ah_stealth_methods(current.collection);
    current.collection &= AH_LOCAL_GROUPS | AH_LOGGEDON | AH_SESSION;
    ah_zip outer(ah_memory_limit(options.mib),options.zip_password);
    auto *previous_sink=ah_archive_sink;auto *previous_zip=ah_loop_zip;
    const bool bounded = ah_bounded_requested(options, profile);
    if (!bounded) { ah_loop_zip=&outer;ah_archive_sink=ah_loop_capture_archive; }
    BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: explicit loop enabled for %llu milliseconds, interval %llu milliseconds; methods %u", static_cast<unsigned long long>(duration_ms), static_cast<unsigned long long>(interval_ms), current.collection);
    for (;;) {
        ULONGLONG now = KERNEL32$GetTickCount64();
        if (now >= deadline) break;
        current.output = ah_loop_filename(options.output, started, ++pass);
        if (!current.output) { BeaconPrintf(CALLBACK_ERROR, "Cannot allocate a unique loop filename; preserving completed passes");break; }
        ah_observe_begin_pass();
        bool complete = collect(current, profile);
        ah_free(current.output);
        ah_observe_end_pass();
        if (!complete) ah_log_level(3, "AdaptiHound: loop pass failed; completed passes remain available and collection will continue");
        if (outer.content().failed) { BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: loop output memory limit reached");break; }
        uint32_t finite_interval = 0;
        if(!ah_timespan_finite_delay(interval_ticks,finite_interval)) { BeaconPrintf(CALLBACK_ERROR,"AdaptiHound: LoopInterval is outside Task.Delay's finite Int32-millisecond interval; completed passes are retained");break; }
        now=KERNEL32$GetTickCount64();

        ULONGLONG wait_until=now>UINT64_MAX-finite_interval?UINT64_MAX:now+finite_interval;
        while((now=KERNEL32$GetTickCount64())<wait_until) {
            ah_drain_observability();
            ULONGLONG remaining=wait_until-now;KERNEL32$Sleep(static_cast<DWORD>(remaining<1000?remaining:1000));
        }
    }
    ah_archive_sink=previous_sink;ah_loop_zip=previous_zip;
    if(!bounded && !(options.runtime_flags&512)) {
        ah_arena names(65536);char timestamp[16];
        char *name=ah_output_timestamp(timestamp)?ah_output_name(names,*options.output?options.output:"BloodHoundLoopResults","zip",timestamp):nullptr;
        if(!name||!outer.download(name,true))BeaconPrintf(CALLBACK_ERROR,"AdaptiHound: loop archive generation failed");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: loop completed, %u additional archives/passes", pass);
}

static void ah_collect(char *args, int length, const ah_profile *profile) {
    ah_options options = {};
    if (!ah_unpack(args, length, options, {AH_DEFAULT, AH_DCONLY, AH_ALL})) { BeaconPrintf(CALLBACK_ERROR, "Invalid AdaptiHound argument buffer or options"); return; }
    ah_verbosity = options.verbosity;
    if (options.legacy_layout) BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: legacy AxScript arguments; reload the extension to enable current options");
    const bool bounded = ah_bounded_requested(options, profile);
    if (ah_memory_auto(options) && !bounded) {
        BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: --memory-auto requires single-domain AD collection without Stealth, ComputerFile or explicit computer targets");
        return;
    }
    ah_memory_scope memory(ah_memory_limit(options.mib), ah_memory_auto(options) ? ah_memory_workspace(options) : 0);
    if (memory.budget.adaptive()) {
        if (memory.budget.limit())
            BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: economical BOF memory mode, initial working watermark %llu bytes; hard ceiling %llu bytes; agent and native API memory are separate",
                static_cast<unsigned long long>(memory.budget.initial_limit()), static_cast<unsigned long long>(memory.budget.limit()));
        else
            BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: economical BOF memory mode, initial working watermark %llu bytes; no user hard ceiling; agent and native API memory are separate",
                static_cast<unsigned long long>(memory.budget.initial_limit()));
    }
    if (profile->security_descriptors && options.mib > 0 && !bounded)
        BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: this option combination uses the standard collection pipeline; multipart collection currently applies to a single domain without Stealth, ComputerFile or explicit computer targets");
    ah_cache_scope cache(options.cache_name,ah_memory_limit(options.mib),
        profile->security_descriptors&&options.wire_version>=4&&!bounded,(options.runtime_flags&4096)!=0);
    ah_observability observations(options.status_interval,(options.option_presence&1)!=0,options.output_prefix,*options.domain?options.domain:options.server);
    if (!observations.valid()) return;
    ah_observe_begin_pass();
    bool complete=ah_collect_pass(options,profile);
    ah_observe_end_pass();
    if (complete && options.loop)
        ah_run_loop(options, profile, [](const ah_options &current, const ah_profile *backend) { return ah_collect_pass(current, backend); });
    cache.finish();
    observations.finish();
    if (memory.budget.adaptive()) {
        if (memory.budget.limit())
            BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: BOF working watermark, initial %llu bytes; reached %llu bytes; hard ceiling %llu bytes; increases %llu",
                static_cast<unsigned long long>(memory.budget.initial_limit()), static_cast<unsigned long long>(memory.budget.working_limit()),
                static_cast<unsigned long long>(memory.budget.limit()), static_cast<unsigned long long>(memory.budget.growth_count()));
        else
            BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: BOF working watermark, initial %llu bytes; reached %llu bytes; no user hard ceiling; increases %llu",
                static_cast<unsigned long long>(memory.budget.initial_limit()), static_cast<unsigned long long>(memory.budget.working_limit()),
                static_cast<unsigned long long>(memory.budget.growth_count()));
    }
    BeaconPrintf(CALLBACK_OUTPUT,"AdaptiHound: BOF-owned heap peak %llu bytes; allocation failures %llu",
        static_cast<unsigned long long>(memory.budget.peak()),static_cast<unsigned long long>(memory.budget.allocation_failures()));
}
