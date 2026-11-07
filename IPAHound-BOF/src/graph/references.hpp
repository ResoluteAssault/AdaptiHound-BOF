#pragma once

static bool ah_ipa_reference_attribute(const ah_object *object, const char *name) {
    const bool ca = ah_weq(object->type, L"ca_acl");
    const bool rule = ca || ah_weq(object->type, L"hbac_rule") || ah_weq(object->type, L"sudo_rule");
    if (rule) return ah_eq(name, "memberUser") || ah_eq(name, "memberHost") || (ca && (ah_eq(name, "memberService") || ah_eq(name, "ipaMemberCertProfile")));
    if (!ah_ipa_kind(object->type)) return false;
    const char *names[] = {"memberOf", "member", "memberManager", "managedBy", "ipaAllowedToPerform;read_keys", "ipaAllowedToPerform;write_keys", "ipaAllowedToPerform;write_delegation", "memberHost", "memberUser", "ipaExternalMember"};
    for (const char *attribute : names) if (ah_eq(name, attribute)) return true;
    return false;
}

static bool ah_ipa_reference_ignored(const char *dn) {
    for (const char *p = dn; *p; ++p)
        if (ah_prefix(p, ",cn=hbac") || ah_prefix(p, ",cn=sudorules") || ah_prefix(p, ",cn=sudocmds,")) return true;
    return false;
}

static const wchar_t *ah_ipa_reference_type(const char *dn) {
    const char *parent = ah_parent(dn);
    if (ah_prefix(parent, "cn=permissions,cn=pbac,")) return L"IPAPermission";
    if (ah_prefix(parent, "cn=privileges,cn=pbac,")) return L"IPAGroup";
    if (ah_prefix(parent, "cn=roles,cn=accounts,")) return L"IPARole";
    if (ah_prefix(parent, "cn=sysaccounts,cn=etc,")) return ah_prefix(dn, "cn=replication managers,") ? L"IPAGroup" : L"IPAUser";
    return L"Base";
}

static bool ah_ipa_resolve_references(ah_directory &directory, ah_index &dns) {
    ah_arena &arena = directory.arena;
    if (!dns.init(arena, directory.count)) return false;
    for (ah_object *o = directory.objects; o; o = o->next) dns.put(o->dn, o);
    size_t missing = 0;
    for (ah_object *o = directory.objects; o && !arena.failed; o = o->next)
        for (ah_attr *a = o->attributes; a; a = a->next) if (ah_ipa_reference_attribute(o, a->name))
            for (ah_value *v = a->values; v; v = v->next) if (*v->data && !ah_ipa_reference_ignored(v->data) && !dns.find(v->data)) {
                if (missing == SIZE_MAX - directory.count) { arena.failed = true; return false; }
                ++missing;
            }
    if (!missing) return !arena.failed;

    if (!dns.init(arena, directory.count + missing)) return false;
    for (ah_object *o = directory.objects; o; o = o->next) dns.put(o->dn, o);
    for (ah_object *o = directory.objects; o && !arena.failed; o = o->next)
        for (ah_attr *a = o->attributes; a; a = a->next) if (ah_ipa_reference_attribute(o, a->name))
            for (ah_value *v = a->values; v && !arena.failed; v = v->next) {
                if (!*v->data || ah_ipa_reference_ignored(v->data) || dns.find(v->data)) continue;
                ah_object *missing_object = directory.add(ah_ipa_reference_type(v->data), v->data);
                if (!missing_object) return false;
                missing_object->placeholder = true;
                const char *name = v->data;
                if (!ah_prefix(name, "S-1-")) {
                    while (*name && *name != '=') ++name;
                    if (*name) ++name; else name = v->data;
                }
                const char *end = name;
                while (*end && *end != ',') ++end;
                ah_attr *cn = directory.attribute(missing_object, "cn");
                directory.value(cn, name, static_cast<size_t>(end - name));
                dns.put(missing_object->dn, missing_object);
            }
    return !arena.failed;
}
