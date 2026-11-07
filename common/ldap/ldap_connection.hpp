#pragma once
static BOOLEAN LDAPAPI ah_ldap_accept_certificate(LDAP *, PCCERT_CONTEXT) { return TRUE; }
static LDAP *ah_bind_ldap(const wchar_t *server, ULONG port, bool secure, ULONG signing, bool ignore_certificate,
    wchar_t *bind_dn, wchar_t *credentials, ULONG authentication, ULONG timeout_seconds, ULONG &status) {
    LDAP *ld = WLDAP32$ldap_sslinitW(const_cast<wchar_t *>(server), port, secure ? 1 : 0);
    if (!ld) { status = LDAP_LOCAL_ERROR; return nullptr; }
    ULONG version = LDAP_VERSION3, off = 0;
    status = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (!status) status = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_REFERRALS, &off);
    if (!status) status = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_SIGN, &signing);
    if (!status) status = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_ENCRYPT, &signing);
    if (!status && secure && ignore_certificate) status = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_SERVER_CERTIFICATE, reinterpret_cast<void *>(ah_ldap_accept_certificate));
    struct l_timeval timeout = {static_cast<long>(timeout_seconds), 0};
    if (!status) status = WLDAP32$ldap_connect(ld, &timeout);
    if (!status) status = WLDAP32$ldap_bind_sW(ld, bind_dn, credentials, authentication);
    if (status) { WLDAP32$ldap_unbind(ld); return nullptr; }
    return ld;
}
