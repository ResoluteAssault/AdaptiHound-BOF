#pragma once
#include "../host/session_credentials.hpp"

class ah_ca_registry_connections final {
    using create_fn = HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using wait_fn = DWORD (WINAPI *)(HANDLE, DWORD);
    using exit_fn = BOOL (WINAPI *)(HANDLE, LPDWORD);
    using open_fn = BOOL (WINAPI *)(HANDLE, DWORD, BOOL, PHANDLE);
    using set_fn = BOOL (WINAPI *)(PHANDLE, HANDLE);
    struct connection {
        ah_ca_registry_connections *owner = nullptr;
        HANDLE thread = nullptr;
        HKEY root = nullptr;
        LONG status = ERROR_GEN_FAILURE;
    } calls[4];
    ah_native_library kernel, advapi;
    create_fn create = nullptr;
    wait_fn wait = nullptr;
    exit_fn exit_code = nullptr;
    set_fn set_token = nullptr;
    HANDLE token = nullptr;
    wchar_t *host = nullptr;
    size_t count = 0;
    LONG initialization = ERROR_PROC_NOT_FOUND;

    static DWORD WINAPI work(void *parameter) {
        connection &call = *static_cast<connection *>(parameter);
        ah_ca_registry_connections &owner = *call.owner;
        if (owner.token && !owner.set_token(nullptr, owner.token)) {
            call.status = ERROR_CANNOT_IMPERSONATE;
            return ERROR_SUCCESS;
        }
        call.status = ADVAPI32$RegConnectRegistryW(owner.host, HKEY_LOCAL_MACHINE, &call.root);
        if (owner.token && !owner.set_token(nullptr, nullptr)) {
            InterlockedIncrement(&ah_token_restore_failures);
            call.status = ERROR_CANNOT_IMPERSONATE;
        }
        return ERROR_SUCCESS;
    }
    void join(connection &call) {
        if (!call.thread) return;
        while (wait(call.thread, 50) != WAIT_OBJECT_0) {
            DWORD code = STILL_ACTIVE;
            if (exit_code(call.thread, &code) && code != STILL_ACTIVE) break;
            KERNEL32$Sleep(1);
        }
        KERNEL32$CloseHandle(call.thread);
        call.thread = nullptr;
    }
public:
    explicit ah_ca_registry_connections(const char *name) : kernel(L"kernel32.dll"), advapi(L"advapi32.dll") {
        create = kernel.find<create_fn>("CreateThread");
        wait = kernel.find<wait_fn>("WaitForSingleObject");
        exit_code = kernel.find<exit_fn>("GetExitCodeThread");
        set_token = advapi.find<set_fn>("SetThreadToken");
        auto open = advapi.find<open_fn>("OpenThreadToken");
        if (!create || !wait || !exit_code || !set_token || !open) return;
        host = ah_wide(name);
        if (!host) { initialization = ERROR_NOT_ENOUGH_MEMORY; return; }
        if (!open(reinterpret_cast<HANDLE>(static_cast<intptr_t>(-2)), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &token) && KERNEL32$GetLastError() != ERROR_NO_TOKEN) {
            initialization = ERROR_CANNOT_IMPERSONATE;
            return;
        }
        initialization = ERROR_SUCCESS;
    }
    ~ah_ca_registry_connections() {
        for (size_t i = 0; i < count; ++i) {
            join(calls[i]);
            if (calls[i].root) ADVAPI32$RegCloseKey(calls[i].root);
        }
        if (token) KERNEL32$CloseHandle(token);
        ah_free(host);
    }
    LONG connect(HKEY *root) {
        *root = nullptr;
        if (initialization != ERROR_SUCCESS) return initialization;
        if (count == sizeof(calls) / sizeof(calls[0])) return ERROR_INVALID_PARAMETER;
        connection &call = calls[count++];
        call.owner = this;
        call.thread = create(nullptr, 0, work, &call, 0, nullptr);
        if (!call.thread) return KERNEL32$GetLastError();
        DWORD result = wait(call.thread, 10000);
        if (result == WAIT_TIMEOUT) return ERROR_TIMEOUT;
        if (result != WAIT_OBJECT_0) return ERROR_GEN_FAILURE;
        join(call);
        if (call.status == ERROR_SUCCESS && !call.root) return ERROR_INVALID_HANDLE;
        if (call.status == ERROR_SUCCESS) {
            *root = call.root;
            call.root = nullptr;
        }
        return call.status;
    }
    ah_ca_registry_connections(const ah_ca_registry_connections &) = delete;
    ah_ca_registry_connections &operator=(const ah_ca_registry_connections &) = delete;
};
