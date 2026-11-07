#pragma once

static const char *ah_registry_wmi_reason(ah_arena &arena, HRESULT status) {
    if (status == HRESULT_FROM_WIN32(RPC_S_SERVER_UNAVAILABLE))
        return "Collector failed: The RPC server is unavailable.\r\n.";
    return ah_win32_failure(arena, "WMI registry connection", static_cast<ULONG>(status));
}

static const char *ah_registry_key_reason(ah_arena &arena, const char *host, const wchar_t *path, LONG status) {
    if (status != ERROR_ACCESS_DENIED && status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND)
        return ah_win32_failure(arena, "RemoteRegistry query", static_cast<ULONG>(status));
    const char *key = arena.utf8(path);
    if (!key) return nullptr;
    ah_buffer exception(0, 4096);
    AH_TEXT(&exception, "SharpHoundRPC.Registry.RemoteRegistryException: Failed to enumerate registry key ");
    ah_append(&exception, key, ah_len(key));
    AH_TEXT(&exception, " ---> ");
    if (status == ERROR_ACCESS_DENIED) {
        AH_TEXT(&exception, "System.Security.SecurityException: Requested registry access is not allowed.\r\n"
            "   at System.ThrowHelper.ThrowSecurityException(ExceptionResource resource)\r\n"
            "   at Microsoft.Win32.RegistryKey.OpenSubKey(String name, Boolean writable)");
    } else {
        AH_TEXT(&exception, "SharpHoundRPC.Registry.RemoteRegistryException: Key not found: ");
        ah_append(&exception, key, ah_len(key));
    }
    AH_TEXT(&exception, "\r\n   at SharpHoundRPC.Registry.RemoteRegistryStrategy.EnumerateKey(RegistryKey baseKey, String keyPath, RegistryQuery query)\r\n"
        "   --- End of inner exception stack trace ---\r\n"
        "   at SharpHoundRPC.Registry.RemoteRegistryStrategy.EnumerateKey(RegistryKey baseKey, String keyPath, RegistryQuery query)\r\n"
        "   at SharpHoundRPC.Registry.RemoteRegistryStrategy.<>c__DisplayClass4_0.<ExecuteAsync>b__0()");
    if (exception.failed) { arena.failed = true; return nullptr; }
    ah_buffer result(0, 4096);
    AH_TEXT(&result, "Collector failed: Failed to enumerate registry on ");
    ah_append(&result, host, ah_len(host)); AH_TEXT(&result, ": ");
    ah_append(&result, exception.data, exception.length);
    AH_TEXT(&result, ".\nInner Exception: ");
    ah_append(&result, exception.data, exception.length);
    if (result.failed) { arena.failed = true; return nullptr; }
    return arena.copy(result.data, result.length);
}

static const char *ah_registry_strategy_reason(ah_arena &arena, const char *wmi, const char *remote) {
    return ah_concat(arena, ah_concat(arena, "DotNetWmiRegistryStrategy: ", wmi ? wmi : ""),
        "\nRemoteRegistryStrategy: ", remote ? remote : "");
}
