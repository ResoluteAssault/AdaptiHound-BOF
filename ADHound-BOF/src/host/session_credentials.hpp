#pragma once

static volatile LONG ah_token_restore_failures = 0;

class ah_session_credentials final {
    ah_native_library advapi;
    using logon_type = BOOL (WINAPI *)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, DWORD, PHANDLE);
    using open_type = BOOL (WINAPI *)(HANDLE, DWORD, BOOL, PHANDLE);
    using impersonate_type = BOOL (WINAPI *)(HANDLE);
    using restore_type = BOOL (WINAPI *)(PHANDLE, HANDLE);
    using revert_type = BOOL (WINAPI *)();
    HANDLE previous = nullptr, alternate = nullptr;
    restore_type restore = nullptr;
    revert_type revert = nullptr;
    bool switched = false, ready = false;
public:
    ah_session_credentials() : advapi(L"advapi32.dll") {
        if (!ah_local_admin_session) { ready = true; return; }
        auto logon = advapi.find<logon_type>("LogonUserW");
        auto open = advapi.find<open_type>("OpenThreadToken");
        auto impersonate = advapi.find<impersonate_type>("ImpersonateLoggedOnUser");
        restore = advapi.find<restore_type>("SetThreadToken");
        revert = advapi.find<revert_type>("RevertToSelf");
        if (!logon || !open || !impersonate || !restore || !revert) return;
        if (!open(reinterpret_cast<HANDLE>(static_cast<intptr_t>(-2)), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &previous) && KERNEL32$GetLastError() != ERROR_NO_TOKEN) return;
        wchar_t *user = ah_wide(ah_local_admin_username), *password = ah_wide(ah_local_admin_password);
        ready = user && password && logon(user, L".", password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &alternate) && impersonate(alternate);
        if (password) { volatile wchar_t *secret = password; size_t n = ah_wlen(password); while (n--) *secret++ = 0; }
        ah_free(user); ah_free(password); switched = ready;
    }
    ~ah_session_credentials() {
        if (switched) {
            if (previous) {
                if (!restore(nullptr, previous)) {
                    revert();
                    if (!restore(nullptr, previous)) {
                        InterlockedIncrement(&ah_token_restore_failures);
                        if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: restoring original thread token failed"); }
                    }
                }
            } else if (!revert()) {
                InterlockedIncrement(&ah_token_restore_failures);
                if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: reverting session credentials failed"); }
            }
        }
        if (previous) KERNEL32$CloseHandle(previous);
        if (alternate) KERNEL32$CloseHandle(alternate);
    }
    bool valid() const { return ready; }
    ah_session_credentials(const ah_session_credentials &) = delete;
    ah_session_credentials &operator=(const ah_session_credentials &) = delete;
};
