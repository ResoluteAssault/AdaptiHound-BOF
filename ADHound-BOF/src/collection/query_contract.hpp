#pragma once

static bool ah_computer_collection(int methods) {
    return (methods & (AH_LOCAL_GROUPS | AH_SESSION | AH_LOGGEDON | AH_USER_RIGHTS | AH_CA_REGISTRY | AH_DC_REGISTRY | AH_WEBCLIENT | AH_SMBINFO | AH_NTLM_REGISTRY | AH_AZURE_REGISTRY)) != 0;
}
static bool ah_broad_collection(int methods) { return (methods & (AH_OBJECT_PROPS | AH_ACL | AH_CONTAINER)) != 0; }
static bool ah_query_enabled(const wchar_t *type, int methods) {
    const bool broad = ah_broad_collection(methods), host = ah_computer_collection(methods);
    if (ah_weq(type, L"domains")) return broad || (methods & AH_TRUSTS);
    if (ah_weq(type, L"users")) return broad || host || (methods & AH_SPN_TARGETS);
    if (ah_weq(type, L"computers")) return broad || host || (methods & AH_LDAP_SERVICES);
    if (ah_weq(type, L"groups")) return broad || (methods & AH_GROUP);
    if (ah_weq(type, L"ous")) return broad || (methods & AH_GPO_LOCAL_GROUP);
    if (ah_weq(type, L"gpos") || ah_weq(type, L"containers")) return broad;
    if (ah_weq(type, L"trusts")) return (methods & AH_TRUSTS) != 0;
    if (ah_weq(type, L"foreignsecurityprincipals")) return broad || (methods & AH_GROUP);
    if (ah_weq(type, L"configuration")) return broad || (methods & (AH_CERT_SERVICES | AH_SITE));
    if (ah_weq(type, L"sites") || ah_weq(type, L"siteservers") || ah_weq(type, L"sitesubnets")) return broad || (methods & AH_SITE);
    if (ah_weq(type, L"enterprisecas")) return broad || (methods & (AH_CERT_SERVICES | AH_CA_REGISTRY));
    if (ah_weq(type, L"rootcas") || ah_weq(type, L"aiacas") || ah_weq(type, L"ntauthstores") || ah_weq(type, L"certtemplates") || ah_weq(type, L"issuancepolicies")) return broad || (methods & AH_CERT_SERVICES);
    if (ah_weq(type, L"directoryservices") || ah_weq(type, L"crossrefs")) return (methods & AH_OBJECT_PROPS) != 0;
    if (ah_weq(type, L"schema")) return (methods & (AH_ACL | AH_CERT_SERVICES)) != 0;
    return false;
}
static const wchar_t *ah_query_filter(const wchar_t *type, int methods) {
    if (ah_weq(type, L"users") && !ah_broad_collection(methods)) {
        if (methods & AH_SPN_TARGETS)
            return ah_computer_collection(methods) ? L"(|(&(|(sAMAccountType=805306368)(sAMAccountType=805306370))(serviceprincipalname=*))(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))" : L"(&(|(sAMAccountType=805306368)(sAMAccountType=805306370))(serviceprincipalname=*))";
        return L"(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))";
    }
    if (ah_weq(type, L"computers") && !ah_broad_collection(methods) && !ah_computer_collection(methods))
        return L"(&(sAMAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))";
    return nullptr;
}
static bool ah_query_name_in(const wchar_t *name, const wchar_t *const *values) {
    for (; *values; ++values) {
        const wchar_t *a=name,*b=*values;
        while(*a&&*b) { wchar_t x=*a++,y=*b++;if(x>=L'A'&&x<=L'Z')x+=32;if(y>=L'A'&&y<=L'Z')y+=32;if(x!=y){a=nullptr;break;} }
        if(a&&!*a&&!*b)return true;
    }
    return false;
}
static bool ah_query_attribute_enabled(const wchar_t *name, int methods, bool configuration) {
    static const wchar_t *const base[] = {L"objectSid",L"distinguishedName",L"objectGUID",L"ms-Mcs-AdmPwdExpirationTime",L"msLAPS-PasswordExpirationTime",L"isDeleted",L"userAccountControl",L"sAMAccountType",L"objectClass",L"sAMAccountName",L"msDS-GroupMSAMembership",L"flags",nullptr};
    static const wchar_t *const group[] = {L"sAMAccountName",L"distinguishedName",L"sAMAccountType",L"member",L"cn",L"primaryGroupID",L"dNSHostName",nullptr};
    static const wchar_t *const host[] = {L"sAMAccountName",L"distinguishedName",L"dNSHostName",L"sAMAccountType",L"operatingSystem",L"pwdLastSet",L"lastLogonTimestamp",L"objectGUID",nullptr};
    static const wchar_t *const acl[] = {L"sAMAccountName",L"distinguishedName",L"dNSHostName",L"sAMAccountType",L"nTSecurityDescriptor",L"displayName",L"objectClass",L"objectSid",L"name",nullptr};
    static const wchar_t *const object_props[] = {L"sAMAccountName",L"distinguishedName",L"sAMAccountType",L"pwdLastSet",L"lastLogon",L"lastLogonTimestamp",L"objectSid",L"sIDHistory",L"dNSHostName",L"operatingSystem",L"operatingSystemServicePack",L"servicePrincipalName",L"displayName",L"mail",L"title",L"homeDirectory",L"description",L"adminCount",L"userPassword",L"gPCFileSysPath",L"objectClass",L"msDS-Behavior-Version",L"objectGUID",L"name",L"gPOptions",L"msDS-AllowedToDelegateTo",L"msDS-AllowedToActOnBehalfOfOtherIdentity",L"whenCreated",L"msDS-HostServiceAccount",L"unixUserPassword",L"msSFU30Password",L"unicodePwd",L"profilePath",L"scriptPath",L"msDS-ExpirePasswordsOnSmartCardOnlyAccounts",L"ms-DS-MachineAccountQuota",L"msDS-SupportedEncryptionTypes",L"dsHeuristics",L"minPwdLength",L"pwdProperties",L"minPwdAge",L"maxPwdAge",L"pwdHistoryLength",L"lockoutDuration",L"lockoutThreshold",L"lockoutObservationWindow",L"groupType",L"msDS-PrincipalName",nullptr};
    static const wchar_t *const container[] = {L"displayName",L"name",L"objectGUID",L"gPLink",L"gPOptions",L"objectClass",nullptr};
    static const wchar_t *const spn[] = {L"servicePrincipalName",L"sAMAccountName",L"sAMAccountType",nullptr};
    static const wchar_t *const trusts[] = {L"trustAttributes",L"securityIdentifier",L"trustDirection",L"trustType",L"cn",nullptr};
    static const wchar_t *const gpo[] = {L"gPLink",L"name",nullptr};
    static const wchar_t *const cert[] = {L"certificateTemplates",L"flags",L"dNSHostName",L"cACertificate",L"msPKI-Certificate-Name-Flag",L"msPKI-Enrollment-Flag",L"displayName",L"name",L"msPKI-Template-Schema-Version",L"msPKI-Cert-Template-OID",L"pKIOverlapPeriod",L"pKIExpirationPeriod",L"pKIExtendedKeyUsage",L"msPKI-RA-Signature",L"msPKI-Certificate-Application-Policy",L"msPKI-Certificate-Policy",L"msPKI-RA-Policies",L"crossCertificatePair",L"msPKI-RA-Application-Policies",L"msPKI-Private-Key-Flag",L"msDS-OIDToGroupLink",nullptr};
    static const wchar_t *const site[] = {L"displayName",L"name",L"objectGUID",L"gPLink",L"gPOptions",L"objectClass",L"description",L"whenCreated",L"dNSHostName",L"serverReference",L"cn",L"siteObject",nullptr};
    if (ah_query_name_in(name, base)) return true;
    if ((methods & AH_OBJECT_PROPS) && ah_query_name_in(name, object_props)) return true;
    if ((methods & AH_ACL) && ah_query_name_in(name, acl)) return true;
    if ((methods & AH_CONTAINER) && ah_query_name_in(name, container)) return true;
    if (configuration) {
        if ((methods & AH_OBJECT_PROPS) && ah_query_name_in(name, site)) return true;
        if ((methods & AH_CONTAINER) && (ah_weq(name,L"siteObject") || ah_weq(name,L"cn"))) return true;
        if ((methods & AH_CERT_SERVICES) && (ah_query_name_in(name, cert) || ah_query_name_in(name, object_props) || ah_query_name_in(name, container) || ah_query_name_in(name, acl))) return true;
        if ((methods & AH_CA_REGISTRY) && ah_query_name_in(name, cert)) return true;
        if ((methods & AH_SITE) && (ah_query_name_in(name, site) || ah_query_name_in(name, acl))) return true;
    } else {
        if ((methods & AH_GROUP) && ah_query_name_in(name, group)) return true;
        if (ah_computer_collection(methods) && ah_query_name_in(name, host)) return true;
        if ((methods & (AH_DC_REGISTRY | AH_LDAP_SERVICES)) && ah_query_name_in(name, host)) return true;
        if ((methods & AH_TRUSTS) && ah_query_name_in(name, trusts)) return true;
        if ((methods & AH_SPN_TARGETS) && ah_query_name_in(name, spn)) return true;
        if ((methods & AH_GPO_LOCAL_GROUP) && ah_query_name_in(name, gpo)) return true;
    }
    return false;
}
