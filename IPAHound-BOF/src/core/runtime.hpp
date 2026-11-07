#pragma once

struct ah_ipa_ldap_handle {
    LDAP *handle, *replacement;
    wchar_t *server;
    bool closed;
    ah_ipa_ldap_handle *next;
};
class ah_directory_runtime final {
public:
    const ah_options &options;
    ah_ipa_ldap_handle *handles = nullptr;
    explicit ah_directory_runtime(const ah_options &value) : options(value) {}
    ~ah_directory_runtime() {
        while (handles) {
            auto *item = handles; handles = item->next;
            if (!item->closed) WLDAP32$ldap_unbind(item->handle);
            ah_free(item->server); ah_free(item);
        }
    }
    ah_directory_runtime(const ah_directory_runtime &) = delete;
    ah_directory_runtime &operator=(const ah_directory_runtime &) = delete;
};
static ah_directory_runtime *ah_ipa_runtime = nullptr;
class ah_ipa_runtime_scope final {
    ah_directory_runtime *previous;
public:
    explicit ah_ipa_runtime_scope(ah_directory_runtime &value) : previous(ah_ipa_runtime) { ah_ipa_runtime = &value; }
    ~ah_ipa_runtime_scope() { ah_ipa_runtime = previous; }
    ah_ipa_runtime_scope(const ah_ipa_runtime_scope &) = delete;
    ah_ipa_runtime_scope &operator=(const ah_ipa_runtime_scope &) = delete;
};
static ah_ipa_ldap_handle *ah_ipa_handle(LDAP *handle) {
    for (auto *item = ah_ipa_runtime ? ah_ipa_runtime->handles : nullptr; item; item = item->next)
        if (item->handle == handle) return item;
    return nullptr;
}
static LDAP *ah_open_ipa_directory(const wchar_t *server, ULONG &status) {
    if (!ah_ipa_runtime) { status = LDAP_LOCAL_ERROR; return nullptr; }
    const ah_options &options = ah_ipa_runtime->options;
    wchar_t *user = ah_wide(options.user), *password = ah_wide(options.password);
    if (!user || !password) { ah_free(user); ah_free(password); status = LDAP_NO_MEMORY; return nullptr; }
    const ULONG port = options.port ? static_cast<ULONG>(options.port) : 636;
    LDAP *handle = ah_bind_ldap(server, port, true, 0, (options.runtime_flags & 4) != 0,
        user, password, LDAP_AUTH_SIMPLE, 30, status);
    ah_free(user);
    volatile wchar_t *secret = password; size_t n = ah_wlen(password); while (n--) *secret++ = 0;
    ah_free(password);
    if (!handle) return nullptr;
    auto *item = ah_alloc<ah_ipa_ldap_handle>(sizeof(ah_ipa_ldap_handle));
    ah_arena temporary(0,4096); const char *name = temporary.utf8(server);
    wchar_t *copy = name ? ah_wide(name) : nullptr;
    if (!item || !copy) {
        ah_free(item); ah_free(copy); WLDAP32$ldap_unbind(handle); status = LDAP_NO_MEMORY; return nullptr;
    }
    *item = {handle, nullptr, copy, false, ah_ipa_runtime->handles};
    ah_ipa_runtime->handles = item;
    return handle;
}
static LDAP *ah_ldap_current(LDAP *handle) {
    for (auto *item = ah_ipa_handle(handle); item && item->replacement; item = ah_ipa_handle(handle)) handle = item->replacement;
    return handle;
}
static void ah_close_directory(LDAP *handle) {
    if (!handle) return;
    handle = ah_ldap_current(handle);
    if (auto *item = ah_ipa_handle(handle)) {
        if (item->closed) return;
        item->closed = true;
    }
    WLDAP32$ldap_unbind(handle);
}
static bool ah_ldap_recover(LDAP *&handle, bool) {
    auto *item = ah_ipa_handle(ah_ldap_current(handle));
    if (!item) return false;
    ULONG status = LDAP_SERVER_DOWN;
    LDAP *replacement = ah_open_ipa_directory(item->server, status);
    if (!replacement) return false;
    item->replacement = replacement; handle = replacement;
    return true;
}
