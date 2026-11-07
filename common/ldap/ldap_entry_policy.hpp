#pragma once
struct ah_ldap_entry_policy {
    bool (*skip)(const char *) = nullptr;
    void (*classify)(ah_directory &, ah_object *, const wchar_t *) = nullptr;
};
