#pragma once
extern "C" {
#define AH_IMPORT(dll, fn) DECLSPEC_IMPORT __typeof__(fn) dll##$##fn
AH_IMPORT(KERNEL32, GetProcessHeap);
AH_IMPORT(KERNEL32, GetTickCount64);
AH_IMPORT(KERNEL32, Sleep);
AH_IMPORT(KERNEL32, InitializeCriticalSectionAndSpinCount);
AH_IMPORT(KERNEL32, EnterCriticalSection);
AH_IMPORT(KERNEL32, LeaveCriticalSection);
AH_IMPORT(KERNEL32, DeleteCriticalSection);
AH_IMPORT(KERNEL32, HeapAlloc);
AH_IMPORT(KERNEL32, HeapReAlloc);
AH_IMPORT(KERNEL32, HeapFree);
AH_IMPORT(KERNEL32, MultiByteToWideChar);
AH_IMPORT(KERNEL32, WideCharToMultiByte);
AH_IMPORT(KERNEL32, LCMapStringW);
AH_IMPORT(KERNEL32, GetSystemTimeAsFileTime);
AH_IMPORT(KERNEL32, CloseHandle);
AH_IMPORT(WLDAP32, ldap_sslinitW);
AH_IMPORT(WLDAP32, ldap_connect);
AH_IMPORT(WLDAP32, ldap_set_optionW);
AH_IMPORT(WLDAP32, ldap_bind_sW);
AH_IMPORT(WLDAP32, ber_bvfree);
AH_IMPORT(WLDAP32, ldap_unbind);
AH_IMPORT(WLDAP32, ldap_search_ext_sW);
AH_IMPORT(WLDAP32, ldap_search_init_pageW);
AH_IMPORT(WLDAP32, ldap_get_next_page_s);
AH_IMPORT(WLDAP32, ldap_search_abandon_page);
AH_IMPORT(WLDAP32, ldap_create_page_controlW);
AH_IMPORT(WLDAP32, ldap_parse_page_controlW);
AH_IMPORT(WLDAP32, ldap_parse_resultW);
AH_IMPORT(WLDAP32, ldap_control_freeW);
AH_IMPORT(WLDAP32, ldap_controls_freeW);
AH_IMPORT(WLDAP32, ldap_first_entry);
AH_IMPORT(WLDAP32, ldap_next_entry);
AH_IMPORT(WLDAP32, ldap_first_attributeW);
AH_IMPORT(WLDAP32, ldap_next_attributeW);
AH_IMPORT(WLDAP32, ldap_get_values_lenW);
AH_IMPORT(WLDAP32, ldap_value_free_len);
AH_IMPORT(WLDAP32, ldap_get_dnW);
AH_IMPORT(WLDAP32, ldap_memfreeW);
AH_IMPORT(WLDAP32, ldap_msgfree);
AH_IMPORT(WLDAP32, ber_free);
DECLSPEC_IMPORT int MSVCRT$_snwprintf(wchar_t *, size_t, const wchar_t *, ...);
}
