#pragma once
static char ah_ad_scope_data[] = {0x30, 0x03, 0x02, 0x01, 0x01};
static LDAPControlW ah_ad_scope_control = {const_cast<wchar_t *>(L"1.2.840.113556.1.4.1340"), {5, ah_ad_scope_data}, TRUE};
static char ah_ad_security_data[] = {0x30, 0x03, 0x02, 0x01, 0x05};
static LDAPControlW ah_ad_security_control = {const_cast<wchar_t *>(L"1.2.840.113556.1.4.801"), {5, ah_ad_security_data}, TRUE};
