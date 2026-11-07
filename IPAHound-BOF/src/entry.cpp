#include "collector.cpp"

static const ah_query ipa_queries[] = {
    {L"IPADomain", L"", L"(objectClass=domain)", LDAP_SCOPE_BASE, 0},
    {L"IPAUser", L"cn=users,cn=accounts,", L"(objectClass=person)", LDAP_SCOPE_SUBTREE, 0},
    {L"IPAUser", L"cn=sysaccounts,cn=etc,", L"(objectClass=account)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPAUser", L"cn=views,cn=accounts,", L"(objectClass=ipaUserOverride)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPAGroup", L"cn=sysaccounts,cn=etc,", L"(objectClass=groupOfNames)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPAGroup", L"cn=groups,cn=accounts,", L"(objectClass=groupOfNames)", LDAP_SCOPE_SUBTREE, 0},
    {L"IPAGroup", L"cn=hostgroups,cn=accounts,", L"(objectClass=groupOfNames)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPAComputer", L"cn=computers,cn=accounts,", L"(objectClass=ipaHost)", LDAP_SCOPE_SUBTREE, 0},
    {L"IPAService", L"cn=services,cn=accounts,", L"(objectClass=ipaService)", LDAP_SCOPE_SUBTREE, 1},
    {L"hbac_service", L"cn=hbacservices,cn=hbac,", L"(objectClass=ipaHBACService)", LDAP_SCOPE_SUBTREE, 1},
    {L"hbac_service", L"cn=hbacservicegroups,cn=hbac,", L"(objectClass=ipaHBACServiceGroup)", LDAP_SCOPE_SUBTREE, 1},
    {L"hbac_rule", L"cn=hbac,", L"(objectClass=ipaHBACRule)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPAPermission", L"cn=permissions,cn=pbac,", L"(objectClass=ipaPermission)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPAGroup", L"cn=privileges,cn=pbac,", L"(objectClass=groupOfNames)", LDAP_SCOPE_SUBTREE, 1},
    {L"sudo_rule", L"cn=sudorules,cn=sudo,", L"(objectClass=ipaSudoRule)", LDAP_SCOPE_SUBTREE, 1},
    {L"sudo_cmd_rule", L"cn=sudocmdgroups,cn=sudo,", L"(objectClass=ipaSudoCmdGrp)", LDAP_SCOPE_SUBTREE, 1},
    {L"sudo_cmd", L"cn=sudocmds,cn=sudo,", L"(objectClass=ipaSudoCmd)", LDAP_SCOPE_SUBTREE, 1},
    {L"ca_acl", L"cn=caacls,cn=ca,", L"(objectClass=ipaCAACL)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPACertificateTemplate", L"cn=certprofiles,cn=ca,", L"(objectClass=ipaCertProfile)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPACA", L"cn=cas,cn=ca,", L"(objectClass=ipaCA)", LDAP_SCOPE_SUBTREE, 1},
    {L"S4U2Proxy", L"cn=s4u2proxy,cn=etc,", L"(objectClass=groupOfPrincipals)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPAGroup", L"cn=ng,cn=alt,", L"(objectClass=ipaNisNetGroup)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPARole", L"cn=roles,cn=accounts,", L"(objectClass=groupOfNames)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPASeLinux", L"cn=usermap,cn=selinux,", L"(objectClass=ipaSELinuxUserMap)", LDAP_SCOPE_SUBTREE, 1},
    {L"IPATrust", L"cn=ad,cn=trusts,", L"(objectClass=ipaNTTrustedDomain)", LDAP_SCOPE_SUBTREE, 1}
};

static const wchar_t *const ipa_attributes[] = {
    L"objectClass", L"cn", L"uid", L"sn", L"fqdn", L"description", L"displayName", L"gecos",
    L"givenName", L"initials", L"mail", L"uidNumber", L"gidNumber", L"homeDirectory", L"loginShell",
    L"info", L"dc", L"nisDomain", L"nisDomainName", L"serverHostName", L"mepManagedEntry", L"mepManagedBy",
    L"associatedDomain", L"ipaNTSecurityIdentifier", L"ipaUniqueID", L"ipaAnchorUUID", L"ipaOriginalUid", L"ipaAllowedTarget",
    L"member", L"memberOf", L"memberHost", L"memberUser", L"memberService", L"memberManager",
    L"managedBy", L"memberPrincipal", L"memberAllowCmd", L"memberDenyCmd", L"ipaExternalMember",
    L"krbPrincipalName", L"krbCanonicalName", L"krbTicketFlags", L"krbPrincipalExpiration",
    L"krbPasswordExpiration", L"krbLastPwdChange", L"krbLastAdminUnlock", L"krbLoginFailedCount",
    L"krbPwdPolicyReference", L"krbExtraData", L"ipaKrbPrincipalAlias", L"ipaUserAuthType", L"nsaccountlock",
    L"ipaEnabledFlag", L"accessRuleType", L"userCategory", L"hostCategory", L"serviceCategory",
    L"cmdCategory", L"ipaSudoCmd", L"sudoCmd", L"ipaSudoOption", L"ipaSudoRunAs", L"ipaSudoRunAsUser",
    L"ipaSudoRunAsGroup", L"ipaSudoRunAsUserCategory", L"ipaSudoRunAsGroupCategory",
    L"ipaAllowedToPerform;read_keys", L"ipaAllowedToPerform;write_keys",
    L"ipaAllowedToPerform;write_delegation", L"ipaMemberCertProfile", L"ipaCertProfileStoreIssued",
    L"ipaCaSubjectDN", L"ipaCaIssuerDN", L"ipaCaId", L"ipaCaRandomSerialNumberVersion",
    L"ipaPermissionType", L"ipaPermBindRuleType", L"ipaPermTargetFrom", L"ipaPermTargetTo", L"ipaPermRight", L"ipaPermTarget",
    L"ipaPermTargetFilter", L"ipaPermLocation", L"ipaPermIncludedAttr", L"ipaPermDefaultAttr",
    L"ipaNTTrustPartner", L"ipaNTTrustDirection", L"ipaNTTrustType", L"ipaNTTrustAttributes",
    L"ipaNTFlatName", L"ipaNTTrustedDomainSID", L"ipaNTDomainGUID", L"ipaSELinuxUser", L"seeAlso",
    L"aci", L"userCertificate", L"userCertificate;binary", NULL
};

extern "C" void go(char *args, int length) {
    const ah_profile profile = {"freeipa", ipa_queries, sizeof(ipa_queries) / sizeof(ipa_queries[0]), ipa_attributes, 0};
    ah_collect(args, length, &profile);
}
