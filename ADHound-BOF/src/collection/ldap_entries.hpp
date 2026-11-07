#pragma once
static bool ah_dn_contains(const char *value, const char *part) {
    for (; *value; ++value) {
        const char *a = value, *b = part;
        while (*a && *b && ah_lower(*a) == ah_lower(*b)) { ++a; ++b; }
        if (!*b) return true;
    }
    return false;
}
static bool ah_dn_starts_with(const char *value,const char *prefix) {
    while(*prefix)if(ah_lower(*value++)!=ah_lower(*prefix++))return false;
    return true;
}
static const char *ah_parent(const char *dn);
static const char *ah_wellknown_kind(const char *sid);
static bool ah_skip_ldap_entry(const char *utf8) {
    return !ah_stealth && (ah_dn_contains(utf8, "cn=domainupdates,cn=system") ||
        (ah_dn_contains(utf8, "cn=policies,cn=system") && (ah_dn_starts_with(utf8, "cn=user") || ah_dn_starts_with(utf8, "cn=machine"))));
}
static void ah_classify_ldap_entry(ah_directory &data, ah_object *object, const wchar_t *type) {
    if(object&&ah_weq(type,L"computerfile")) {
        object->explicit_target=true;object->auxiliary_only=false;
        uint64_t account=ah_unsigned(object->text("sAMAccountType"));
        object->type=account==805306369?L"computers":account==805306368||account==805306370?L"users":
            account==268435456||account==268435457||account==536870912||account==536870913?L"groups":L"computerfile";
        for(ah_value *v=object->values("objectClass");v;v=v->next) {
            if(ah_eq(v->data,"msDS-ManagedServiceAccount")||ah_eq(v->data,"msDS-GroupManagedServiceAccount"))object->type=L"users";
            else if(ah_eq(v->data,"domainDNS"))object->type=L"domains";
            else if(ah_eq(v->data,"organizationalUnit"))object->type=L"ous";
        }
    }
    if(object&&(ah_weq(type,L"stealthdefault")||ah_weq(type,L"stealthconfiguration"))) {

        object->explicit_target=true;
        auto has_class=[&](const char *name) {
            for(ah_value *value=object->values("objectClass");value;value=value->next)
                if(ah_eq(value->data,name))return true;
            return false;
        };
        const uint64_t account=ah_unsigned(object->text("sAMAccountType"));
        const ah_value *sid_value=object->values("objectSid");
        const char *sid=sid_value?ah_sid(data.arena,reinterpret_cast<const unsigned char *>(sid_value->data),sid_value->size):nullptr;
        const char *wellknown=sid?ah_wellknown_kind(sid):nullptr;
        object->type=L"stealthunsupported";
        if(wellknown)object->type=ah_eq(wellknown,"User")?L"users":ah_eq(wellknown,"Computer")?L"computers":ah_eq(wellknown,"Group")?L"groups":L"stealthunsupported";
        else if(has_class("msDS-ManagedServiceAccount")||has_class("msDS-GroupManagedServiceAccount"))object->type=L"users";
        else if(account==805306369)object->type=L"computers";
        else if(account==805306368||account==805306370)object->type=L"users";
        else if(account==268435456||account==268435457||account==536870912||account==536870913)object->type=L"groups";
        else if(has_class("groupPolicyContainer"))object->type=L"gpos";
        else if(has_class("organizationalUnit"))object->type=L"ous";
        else if(has_class("domainDNS")||has_class("domain"))object->type=L"domains";
        else if(has_class("container"))object->type=L"containers";
        else if(has_class("configuration"))object->type=L"configuration";
        else if(has_class("builtinDomain")||has_class("sitesContainer"))object->type=L"containers";
        else if(has_class("pKICertificateTemplate"))object->type=L"certtemplates";
        else if(has_class("pKIEnrollmentService"))object->type=L"enterprisecas";
        else if(has_class("certificationAuthority")) {
            if(ah_dn_contains(object->dn,"CN=Certification Authorities,CN=Public Key Services,CN=Services"))object->type=L"rootcas";
            if(ah_dn_contains(object->dn,"CN=AIA,CN=Public Key Services,CN=Services"))object->type=L"aiacas";
            if(ah_dn_contains(object->dn,"CN=NTAuthCertificates,CN=Public Key Services,CN=Services"))object->type=L"ntauthstores";
        }
        else if(has_class("msPKI-Enterprise-Oid"))object->type=L"issuancepolicies";
        else if(has_class("site"))object->type=L"sites";
        else if(has_class("server")) {
            for(const char *parent=object->dn;*parent;parent=ah_parent(parent))
                if(ah_dn_starts_with(parent,"CN=Sites,CN=Configuration,")) { object->type=L"siteservers";break; }
        }
        else if(has_class("subnet"))object->type=L"sitesubnets";
    }
}
static const ah_ldap_entry_policy ah_ad_entry_policy = {ah_skip_ldap_entry, ah_classify_ldap_entry};
