#pragma once

struct ah_producer_parameters {
    const wchar_t *filter;
    const wchar_t *const *attributes;
    bool enabled;
};

class ah_producer_list final {
    struct item { const wchar_t *value; item *next; };
    ah_arena &arena;
    item *first = nullptr, *last = nullptr;
    size_t count = 0;
public:
    explicit ah_producer_list(ah_arena &owner) : arena(owner) {}
    bool add(const wchar_t *value) {
        for (item *entry = first; entry; entry = entry->next)
            if (ah_weq(entry->value, value)) return true;
        item *entry = arena.make<item>();
        if (!entry) return false;
        entry->value = value; entry->next = nullptr;
        if (last) last->next = entry; else first = entry;
        last = entry; ++count; return true;
    }
    bool append(const wchar_t *const *values) {
        for (; *values; ++values) if (!add(*values)) return false;
        return true;
    }
    const wchar_t *const *attributes() {
        if (count >= SIZE_MAX / sizeof(const wchar_t *)) { arena.failed = true; return nullptr; }
        auto values = static_cast<const wchar_t **>(arena.alloc((count + 1) * sizeof(const wchar_t *)));
        if (!values) return nullptr;
        size_t index = 0;
        for (item *entry = first; entry; entry = entry->next) values[index++] = entry->value;
        values[index] = nullptr; return values;
    }
    const wchar_t *filter(const wchar_t *mandatory) {

        size_t optional_count = 0, length = mandatory ? 3 : 0;
        if (mandatory) {
            size_t n = ah_wlen(mandatory);
            if (n > SIZE_MAX - length) { arena.failed = true; return nullptr; }
            length += n;
        }
        for (item *entry = first; entry; entry = entry->next) {
            if (mandatory && ah_weq(entry->value, mandatory)) continue;
            size_t n = ah_wlen(entry->value);
            if (n > SIZE_MAX - length) { arena.failed = true; return nullptr; }
            length += n; ++optional_count;
        }
        if (optional_count > 1) {
            if (length > SIZE_MAX - 3) { arena.failed = true; return nullptr; }
            length += 3;
        }
        if (length >= SIZE_MAX / sizeof(wchar_t)) { arena.failed = true; return nullptr; }
        auto result = static_cast<wchar_t *>(arena.alloc((length + 1) * sizeof(wchar_t)));
        if (!result) return nullptr;
        wchar_t *out = result;
        if (mandatory) { *out++ = L'('; *out++ = L'&'; }
        if (optional_count > 1) { *out++ = L'('; *out++ = L'|'; }
        for (item *entry = first; entry; entry = entry->next) {
            if (mandatory && ah_weq(entry->value, mandatory)) continue;
            for (const wchar_t *p = entry->value; *p; ++p) *out++ = *p;
        }
        if (optional_count > 1) *out++ = L')';
        if (mandatory) {
            for (const wchar_t *p = mandatory; *p; ++p) *out++ = *p;
            *out++ = L')';
        }
        *out = 0; return result;
    }
};

static bool ah_stealth_parameters(ah_arena &arena, int methods,
                                  const char *custom_filter, bool configuration,
                                  ah_producer_parameters &out) {
    out = {nullptr, nullptr, false};
    const bool broad = (methods & (AH_OBJECT_PROPS | AH_ACL | AH_CONTAINER)) != 0;
    const bool computers = (methods & (AH_LOCAL_GROUPS | AH_SESSION | AH_USER_RIGHTS |
        AH_CA_REGISTRY | AH_DC_REGISTRY | AH_WEBCLIENT | AH_SMBINFO |
        AH_NTLM_REGISTRY | AH_AZURE_REGISTRY | AH_LOGGEDON)) != 0;
    out.enabled = !configuration || broad ||
        (methods & (AH_CERT_SERVICES | AH_SITE | AH_CA_REGISTRY)) || custom_filter != nullptr;
    if (!out.enabled) return !arena.failed;

    static const wchar_t *const BaseQueryProps[] = {
        L"objectsid", L"distinguishedname", L"objectguid", L"ms-mcs-admpwdexpirationtime", L"mslaps-passwordexpirationtime", L"isdeleted", L"useraccountcontrol", nullptr
    };
    static const wchar_t *const TypeResolutionProps[] = {
        L"samaccounttype", L"objectsid", L"objectguid", L"objectclass", L"samaccountname", L"msds-groupmsamembership", L"flags", nullptr
    };
    static const wchar_t *const ContainerProps[] = {
        L"displayname", L"name", L"objectguid", L"gplink", L"gpoptions", L"objectclass", nullptr
    };
    static const wchar_t *const GroupResolutionProps[] = {
        L"samaccountname", L"distinguishedname", L"samaccounttype", L"member", L"cn", L"primarygroupid", L"dnshostname", nullptr
    };
    static const wchar_t *const ACLProps[] = {
        L"samaccountname", L"distinguishedname", L"dnshostname", L"samaccounttype", L"ntsecuritydescriptor", L"displayname", L"objectclass", L"objectsid", L"name", nullptr
    };
    static const wchar_t *const ObjectPropsProps[] = {
        L"samaccountname", L"distinguishedname", L"samaccounttype", L"pwdlastset", L"lastlogon", L"lastlogontimestamp", L"objectsid", L"sidhistory", L"dnshostname", L"operatingsystem", L"operatingsystemservicepack", L"serviceprincipalname", L"displayname", L"mail", L"title", L"homedirectory", L"description", L"admincount", L"userpassword", L"gpcfilesyspath", L"objectclass", L"msds-behavior-version", L"objectguid", L"name", L"gpoptions", L"msds-allowedtodelegateto", L"msds-allowedtoactonbehalfofotheridentity", L"whencreated", L"msds-hostserviceaccount", L"unixuserpassword", L"msSFU30Password", L"unicodepwd", L"profilepath", L"scriptpath", L"msds-expirepasswordsonsmartcardonlyaccounts", L"ms-ds-machineaccountquota", L"msds-supportedencryptiontypes", L"dsheuristics", L"minpwdlength", L"pwdproperties", L"minpwdage", L"maxpwdage", L"pwdhistorylength", L"lockoutduration", L"lockoutthreshold", L"lockoutobservationwindow", L"grouptype", L"msds-principalname", nullptr
    };
    static const wchar_t *const ComputerMethodProps[] = {
        L"samaccountname", L"distinguishedname", L"dnshostname", L"samaccounttype", L"operatingsystem", L"pwdlastset", L"lastlogontimestamp", L"objectguid", nullptr
    };
    static const wchar_t *const DomainTrustProps[] = {
        L"trustattributes", L"securityidentifier", L"trustdirection", L"trusttype", L"cn", nullptr
    };
    static const wchar_t *const GPOLocalGroupProps[] = {
        L"gplink", L"name", nullptr
    };
    static const wchar_t *const SPNTargetProps[] = {
        L"serviceprincipalname", L"samaccountname", L"samaccounttype", nullptr
    };
    ah_producer_list filters(arena), properties(arena);
    if (!properties.append(BaseQueryProps) || !properties.append(TypeResolutionProps)) return false;
    if (broad) {
        if (!filters.add(L"(samaccounttype=805306369)") ||
            !filters.add(L"(objectclass=domain)") ||
            !filters.add(L"(|(samaccounttype=805306368)(samaccounttype=805306370))") ||
            !filters.add(L"(&(!(objectClass=groupPolicyContainer))(objectClass=container))") ||
            !filters.add(L"(objectClass=builtinDomain)") ||
            !filters.add(L"(&(objectcategory=groupPolicyContainer)(flags=*))") ||
            !filters.add(L"(objectcategory=organizationalUnit)") ||
            !filters.add(L"(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))")) return false;
        if ((methods & AH_CONTAINER) && !properties.append(ContainerProps)) return false;
        if ((methods & AH_GROUP) && !properties.append(GroupResolutionProps)) return false;
        if ((methods & AH_ACL) && !properties.append(ACLProps)) return false;
        if ((methods & AH_OBJECT_PROPS) && !properties.append(ObjectPropsProps)) return false;
        if (computers && !properties.append(ComputerMethodProps)) return false;
        if ((methods & AH_TRUSTS) && !properties.append(DomainTrustProps)) return false;
        if ((methods & AH_GPO_LOCAL_GROUP) && !properties.append(GPOLocalGroupProps)) return false;
        if ((methods & AH_SPN_TARGETS) && !properties.append(SPNTargetProps)) return false;
    } else {
        if (computers && (!filters.add(L"(samaccounttype=805306369)") ||
                          !properties.append(ComputerMethodProps))) return false;

        if ((methods & AH_TRUSTS) && (!filters.add(L"(objectclass=domain)") ||
                                      !properties.append(ComputerMethodProps))) return false;
        if ((methods & AH_SPN_TARGETS) &&
            (!filters.add(L"(&(|(samaccounttype=805306368)(samaccounttype=805306370))(serviceprincipalname=*))") ||
             !properties.append(SPNTargetProps))) return false;
        if ((methods & AH_GPO_LOCAL_GROUP) &&
            (!filters.add(L"(objectcategory=organizationalUnit)") ||
             !properties.append(GPOLocalGroupProps))) return false;
        if ((methods & (AH_DC_REGISTRY | AH_LDAP_SERVICES)) &&
            (!filters.add(L"(&(samaccounttype=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192))") ||
             !properties.append(ComputerMethodProps))) return false;
        if ((methods & AH_GROUP) &&
            (!filters.add(L"(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))") ||
             !properties.append(GroupResolutionProps))) return false;
    }

    const wchar_t *mandatory = nullptr;
    if (custom_filter) {
        wchar_t *wide = ah_wide(custom_filter);
        if (!wide) { arena.failed = true; return false; }
        const size_t n = ah_wlen(wide);
        const bool prepend = !n || wide[0] != L'(';
        const bool append = !n || wide[n - 1] != L')';
        if (n > SIZE_MAX - 3 || n + 3 > SIZE_MAX / sizeof(wchar_t)) {
            ah_free(wide); arena.failed = true; return false;
        }
        auto fixed = static_cast<wchar_t *>(arena.alloc((n + 3) * sizeof(wchar_t)));
        if (!fixed) { ah_free(wide); return false; }
        wchar_t *p = fixed;
        if (prepend) *p++ = L'(';
        for (size_t i = 0; i < n; ++i) *p++ = wide[i];
        if (append) *p++ = L')';
        *p = 0; ah_free(wide); mandatory = fixed;
    }
    out.filter = filters.filter(mandatory);
    out.attributes = properties.attributes();
    return out.filter && out.attributes && !arena.failed;
}
