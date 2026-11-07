#pragma once

static ah_object *ah_read_linked_gpo(ah_graph &graph, LDAP *ld, const wchar_t *base, const char *dn) {
    wchar_t *attributes[] = {const_cast<wchar_t *>(L"objectGUID"), const_cast<wchar_t *>(L"gPCFileSysPath"), const_cast<wchar_t *>(L"flags"), nullptr};
    struct result_guard final {
        LDAPMessage *value = nullptr;
        ~result_guard() { if (value) WLDAP32$ldap_msgfree(value); }
    } result;
    struct l_timeval timeout = {ah_ldap_query_timeout_seconds, 0};
    ULONG status = ah_ldap_search_retry(ld, const_cast<wchar_t *>(base), LDAP_SCOPE_BASE,
        const_cast<wchar_t *>(L"(objectClass=*)"), attributes, 0, nullptr, nullptr, &timeout, 1, &result.value);
    LDAPMessage *entry = !status && result.value ? WLDAP32$ldap_first_entry(ld, result.value) : nullptr;
    if (!entry) return nullptr;
    ah_object *object = graph.arena.make<ah_object>();
    if (!object) return nullptr;
    object->type = L"gpos"; object->kind = "GPO"; object->dn = graph.arena.copy(dn);
    const char *names[] = {"objectGUID", "gPCFileSysPath", "flags"};
    for (unsigned int i = 0; i < 3; ++i) {
        struct berval **values = WLDAP32$ldap_get_values_lenW(ld, entry, attributes[i]);
        if (values && values[0]) {
            graph.directory.value(graph.directory.attribute(object, names[i]), values[0]->bv_val, values[0]->bv_len);
            if (!i) object->id = ah_guid(graph.arena, reinterpret_cast<unsigned char *>(values[0]->bv_val), values[0]->bv_len);
        }
        if (values) WLDAP32$ldap_value_free_len(values);
    }

    return graph.arena.failed ? nullptr : object;
}

static ah_object *ah_resolve_linked_gpo(ah_graph &graph, const char *dn) {
    if (!dn || !*dn) return nullptr;
    ah_directory_guard guard(graph);
    if (ah_object *object = graph.dns.find(dn)) if (ah_weq(object->type, L"gpos")) return object;

    for (ah_gpo_cache_entry *cached = graph.gpo_cache; cached; cached = cached->next)
        if (cached->gpo && ah_eq(cached->gpo->dn, dn)) return cached->gpo;
    auto *runtime = ah_runtime_for(graph);
    if (!ah_runtime_primary(runtime)) return nullptr;
    wchar_t *base = ah_wide(dn);
    if (!base) return nullptr;
    ah_object *object = ah_read_linked_gpo(graph, runtime->primary, base, dn);
    if (!object) {
        ah_object context = {}; context.dn = const_cast<char *>(dn);
        const char *domain = graph.object_domain(&context);
        if (domain && *domain && !ah_eq(domain, graph.domain) && !*runtime->options.server) {
            wchar_t *wide = ah_wide(domain); PDOMAIN_CONTROLLER_INFOW dc = nullptr;
            if (wide && NETAPI32$DsGetDcNameW(nullptr, wide, nullptr, nullptr, DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME, &dc) == ERROR_SUCCESS && dc) {
                const wchar_t *host = dc->DomainControllerName;
                if (host && host[0] == '\\' && host[1] == '\\') host += 2;
                ULONG status = LDAP_LOCAL_ERROR;
                LDAP *ld = host ? ah_open_directory(host, runtime->options, false, 10, status) : nullptr;
                if (ld) { object = ah_read_linked_gpo(graph, ld, base, dn); ah_close_directory(ld); }
            }
            if (dc) NETAPI32$NetApiBufferFree(dc);
            ah_free(wide);
        }
    }
    ah_free(base);
    return graph.arena.failed ? nullptr : object;
}
