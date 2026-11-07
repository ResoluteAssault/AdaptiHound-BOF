#include "collector.cpp"

static const ah_query ad_queries[] = {
    {L"domains", L"", L"(objectClass=domainDNS)", LDAP_SCOPE_BASE, 0},
    {L"users", L"", L"(|(sAMAccountType=805306368)(sAMAccountType=805306370)(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))", LDAP_SCOPE_SUBTREE, 0},
    {L"computers", L"", L"(&(sAMAccountType=805306369)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))", LDAP_SCOPE_SUBTREE, 0},
    {L"groups", L"", L"(|(sAMAccountType=268435456)(sAMAccountType=268435457)(sAMAccountType=536870912)(sAMAccountType=536870913))", LDAP_SCOPE_SUBTREE, 0},
    {L"ous", L"", L"(objectClass=organizationalUnit)", LDAP_SCOPE_SUBTREE, 0},
    {L"gpos", L"", L"(&(objectCategory=groupPolicyContainer)(flags=*))", LDAP_SCOPE_SUBTREE, 0},
    {L"containers", L"", L"(&(|(objectClass=container)(objectClass=builtinDomain))(!(objectClass=groupPolicyContainer)))", LDAP_SCOPE_SUBTREE, 0},
    {L"trusts", L"", L"(objectClass=trustedDomain)", LDAP_SCOPE_SUBTREE, 0},
    {L"foreignsecurityprincipals", L"", L"(objectClass=foreignSecurityPrincipal)", LDAP_SCOPE_SUBTREE, 0},
    {L"configuration", L"", L"(|(objectClass=container)(objectClass=builtinDomain)(objectClass=configuration)(objectClass=sitesContainer))", LDAP_SCOPE_SUBTREE, 0},
    {L"sites", L"CN=Sites,", L"(objectClass=site)", LDAP_SCOPE_SUBTREE, 0},
    {L"siteservers", L"CN=Sites,", L"(objectClass=server)", LDAP_SCOPE_SUBTREE, 0},
    {L"sitesubnets", L"CN=Sites,", L"(objectClass=subnet)", LDAP_SCOPE_SUBTREE, 0},
    {L"rootcas", L"CN=Certification Authorities,CN=Public Key Services,CN=Services,", L"(objectClass=certificationAuthority)", LDAP_SCOPE_SUBTREE, 0},
    {L"aiacas", L"CN=AIA,CN=Public Key Services,CN=Services,", L"(objectClass=certificationAuthority)", LDAP_SCOPE_SUBTREE, 0},
    {L"enterprisecas", L"CN=Enrollment Services,CN=Public Key Services,CN=Services,", L"(objectClass=pKIEnrollmentService)", LDAP_SCOPE_SUBTREE, 0},
    {L"ntauthstores", L"CN=NTAuthCertificates,CN=Public Key Services,CN=Services,", L"(objectClass=certificationAuthority)", LDAP_SCOPE_SUBTREE, 1},
    {L"certtemplates", L"CN=Certificate Templates,CN=Public Key Services,CN=Services,", L"(objectClass=pKICertificateTemplate)", LDAP_SCOPE_SUBTREE, 0},
    {L"issuancepolicies", L"CN=OID,CN=Public Key Services,CN=Services,", L"(objectClass=msPKI-Enterprise-Oid)", LDAP_SCOPE_SUBTREE, 0},
    {L"directoryservices", L"CN=Directory Service,CN=Windows NT,CN=Services,", L"(objectClass=nTDSService)", LDAP_SCOPE_BASE, 1},
    {L"crossrefs", L"CN=Partitions,", L"(objectClass=crossRef)", LDAP_SCOPE_SUBTREE, 1}
};

static const wchar_t *const ad_attributes[] = {
    L"objectClass", L"objectSid", L"objectGUID", L"sAMAccountName", L"name", L"displayName",
    L"distinguishedName", L"description", L"member", L"memberOf", L"primaryGroupID", L"sAMAccountType",
    L"userAccountControl", L"adminCount", L"servicePrincipalName", L"sIDHistory",
    L"nTSecurityDescriptor", L"msDS-AllowedToDelegateTo", L"msDS-AllowedToActOnBehalfOfOtherIdentity",
    L"dNSHostName", L"operatingSystem", L"operatingSystemServicePack", L"operatingSystemVersion",
    L"pwdLastSet", L"lastLogon", L"lastLogonTimestamp", L"whenCreated", L"accountExpires",
    L"mail", L"title", L"homeDirectory", L"scriptPath", L"gPCFileSysPath", L"gPLink", L"gPOptions",
    L"userPassword", L"unixUserPassword", L"msSFU30Password", L"unicodePwd",
    L"serverReference", L"siteObject", L"nETBIOSName", L"nCName",
    L"msDS-Behavior-Version", L"ms-Mcs-AdmPwdExpirationTime", L"msLAPS-PasswordExpirationTime",
    L"trustPartner", L"trustDirection", L"trustType", L"trustAttributes", L"securityIdentifier",
    L"cn", L"flags", L"cACertificate", L"certificateTemplates", L"crossCertificatePair",
    L"msPKI-Cert-Template-OID", L"msPKI-Template-Schema-Version", L"msPKI-Template-Minor-Revision",
    L"msPKI-Enrollment-Flag", L"msPKI-Certificate-Name-Flag", L"msPKI-Certificate-Application-Policy",
    L"msPKI-Certificate-Policy", L"msPKI-RA-Signature", L"msPKI-RA-Policies", L"msPKI-RA-Application-Policies",
    L"msPKI-Minimal-Key-Size", L"msDS-OIDToGroupLink", L"msDS-GroupMSAMembership", L"msDS-HostServiceAccount",
    L"msPKI-Private-Key-Flag", L"pKIExtendedKeyUsage", L"pKIDefaultKeySpec", L"pKIKeyUsage",
    L"pKIMaxIssuingDepth", L"pKIExpirationPeriod", L"pKIOverlapPeriod", L"accountExpires",
    L"lockoutDuration", L"lockoutObservationWindow", L"lockoutThreshold", L"ms-DS-MachineAccountQuota",
    L"maxPwdAge", L"minPwdAge", L"minPwdLength", L"pwdHistoryLength", L"pwdProperties",
    L"ms-DS-Logon-Time-Sync-Interval", L"dsHeuristics", L"profilePath", L"lockoutTime",
    L"msDS-SupportedEncryptionTypes", L"msDS-AADObjectID", L"msDS-PrincipalName",
    L"msDS-ExpirePasswordsOnSmartCardOnlyAccounts", L"groupType", L"isDeleted", NULL
};

extern "C" void go(char *args, int length) {
    const ah_profile profile = {"ad", ad_queries, sizeof(ad_queries) / sizeof(ad_queries[0]), ad_attributes, 1};
    ah_collect(args, length, &profile);
}
