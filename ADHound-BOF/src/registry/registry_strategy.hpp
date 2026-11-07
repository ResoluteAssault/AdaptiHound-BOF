#pragma once
#include "registry_status.hpp"

static bool ah_wmi_registry_key(ah_wmi_connection &connection, IWbemClassObject *provider, const wchar_t *path, const wchar_t *value_name, DWORD *value_type, bool *exists, const char **failure) {
    *exists = false;
    ah_automation &api = connection.automation;
    IWbemClassObject *signature = nullptr, *input = nullptr, *output = nullptr;
    if (FAILED(provider->GetMethod(L"EnumValues", 0, &signature, nullptr)) || !signature) return false;
    HRESULT status = signature->SpawnInstance(0, &input); signature->Release();
    if (FAILED(status) || !input) return false;
    VARIANT hive = {}; hive.vt = VT_I4; hive.lVal = static_cast<LONG>(0x80000002U);
    bool ready = SUCCEEDED(input->Put(L"hDefKey", 0, &hive, CIM_UINT32)) && ah_wmi_put_string(api, input, L"sSubKeyName", path);
    ah_bstr object(api, L"StdRegProv"), method(api, L"EnumValues");
    IWbemCallResult *call = nullptr;
    if (ready && object.value && method.value) {
        status = connection.services->ExecMethod(object.value, method.value, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, input, nullptr, &call);
        if (SUCCEEDED(status) && call) status = connection.secure(call);
        if (SUCCEEDED(status) && call) status = call->GetResultObject(5000, &output);
    }
    input->Release(); if (call) call->Release();
    if (FAILED(status) || status == WBEM_S_TIMEDOUT || !output) { if (output) output->Release(); return false; }
    VARIANT code = {};

    bool ok = SUCCEEDED(output->Get(L"ReturnValue", 0, &code, nullptr, nullptr)) && (code.vt == VT_I4 || code.vt == VT_UI4);
    if (ok) {
        VARIANT names = {}, types = {};
        ok = SUCCEEDED(output->Get(L"sNames", 0, &names, nullptr, nullptr)) && SUCCEEDED(output->Get(L"Types", 0, &types, nullptr, nullptr));
        if (ok && names.vt == VT_NULL && types.vt == VT_NULL) {

            *failure = "Collector failed: Value cannot be null.\r\nParameter name: array.";
            ok = false;
        } else if (ok && names.vt == (VT_ARRAY | VT_BSTR) && (types.vt == (VT_ARRAY | VT_I4) || types.vt == (VT_ARRAY | VT_UI4)) && names.parray && types.parray) {
            ah_native_library automation(L"oleaut32.dll");
            auto dimensions = automation.find<decltype(&SafeArrayGetDim)>("SafeArrayGetDim");
            auto lower = automation.find<decltype(&SafeArrayGetLBound)>("SafeArrayGetLBound");
            auto upper = automation.find<decltype(&SafeArrayGetUBound)>("SafeArrayGetUBound");
            auto access = automation.find<decltype(&SafeArrayAccessData)>("SafeArrayAccessData");
            auto unaccess = automation.find<decltype(&SafeArrayUnaccessData)>("SafeArrayUnaccessData");
            ah_native_library kernel(L"kernel32.dll");
            auto compare = kernel.find<decltype(&CompareStringOrdinal)>("CompareStringOrdinal");
            LONG nl = 0, nh = -1, tl = 0, th = -1;
            ok = dimensions && lower && upper && access && unaccess && compare && dimensions(names.parray) == 1 && dimensions(types.parray) == 1 &&
                SUCCEEDED(lower(names.parray, 1, &nl)) && SUCCEEDED(upper(names.parray, 1, &nh)) && SUCCEEDED(lower(types.parray, 1, &tl)) && SUCCEEDED(upper(types.parray, 1, &th)) &&
                static_cast<int64_t>(nh) - nl == static_cast<int64_t>(th) - tl && static_cast<int64_t>(nh) - nl < 1000000;
            BSTR *name_data = nullptr; LONG *type_data = nullptr;
            if (ok) {
                ok = SUCCEEDED(access(names.parray, reinterpret_cast<void **>(&name_data)));
                if (ok) {
                    bool types_opened = SUCCEEDED(access(types.parray, reinterpret_cast<void **>(&type_data)));
                    ok = types_opened && (nh < nl || (name_data && type_data));
                    if (ok) for (int64_t i = 0; i <= static_cast<int64_t>(nh) - nl; ++i)
                        if (name_data[i] && compare(name_data[i], -1, value_name, -1, TRUE) == CSTR_EQUAL) { *exists = true; *value_type = static_cast<DWORD>(type_data[i]); break; }
                    if (types_opened) unaccess(types.parray);
                    unaccess(names.parray);
                }
            }
        } else ok = false;
        api.clear(&names); api.clear(&types);
    }
    api.clear(&code); output->Release(); return ok;
}

static LONG ah_registry_query_value(ah_arena &arena, HKEY key, const ah_registry_wmi_query &query) {
    DWORD type = 0, size = 0;
    LONG status = ADVAPI32$RegQueryValueExW(key, query.name, nullptr, &type, nullptr, &size);
    if (status == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
    if (status != ERROR_SUCCESS) return status;
    if (size > 16 * 1024 * 1024 || ((type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) && size % sizeof(wchar_t))) return ERROR_INVALID_DATA;
    unsigned char *data = ah_alloc<unsigned char>(static_cast<size_t>(size) + 2 * sizeof(wchar_t));
    if (!data) return ERROR_NOT_ENOUGH_MEMORY;
    for (unsigned int i = 0; i < 2 * sizeof(wchar_t); ++i) data[size + i] = 0;
    DWORD expected_type = type, capacity = size;
    status = ADVAPI32$RegQueryValueExW(key, query.name, nullptr, &type, data, &size);
    if (status == ERROR_SUCCESS && (type != expected_type || size > capacity)) status = ERROR_INVALID_DATA;
    uint64_t number = 0; bool signed_number = false;
    if (status == ERROR_SUCCESS && (type == REG_DWORD || type == REG_QWORD)) {
        if (size != (type == REG_DWORD ? 4U : 8U)) status = ERROR_INVALID_DATA;
        else {
            number = ah_u32(data);
            if (type == REG_QWORD) number |= static_cast<uint64_t>(ah_u32(data + 4)) << 32;
            else number = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(number)));
            signed_number = true;
        }
    }
    wchar_t *expanded = nullptr;
    const wchar_t *text = reinterpret_cast<wchar_t *>(data);
    if (status == ERROR_SUCCESS && type == REG_EXPAND_SZ) {
        ah_native_library kernel(L"kernel32.dll");
        auto expand = kernel.find<decltype(&ExpandEnvironmentStringsW)>("ExpandEnvironmentStringsW");
        DWORD length = expand ? expand(text, nullptr, 0) : 0;
        if (!length || length > 8 * 1024 * 1024) status = ERROR_INVALID_DATA;
        else {
            expanded = ah_alloc<wchar_t>(static_cast<size_t>(length) * sizeof(wchar_t));
            if (!expanded) status = ERROR_NOT_ENOUGH_MEMORY;
            else if (!expand(text, expanded, length)) status = ERROR_INVALID_DATA;
            else text = expanded;
        }
    }
    if (status == ERROR_SUCCESS && query.number) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            if (!ah_registry_unsigned_text(text, 0xffffffffULL, number)) status = ERROR_INVALID_DATA;
        } else if (type != REG_DWORD && type != REG_QWORD) status = ERROR_INVALID_DATA;
        if (status == ERROR_SUCCESS && number > 0xffffffffULL) status = ERROR_ARITHMETIC_OVERFLOW;
        if (status == ERROR_SUCCESS) *query.number = static_cast<uint32_t>(number);
    } else if (status == ERROR_SUCCESS && query.text) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) *query.text = arena.utf8(text);
        else if (type == REG_DWORD || type == REG_QWORD) *query.text = ah_registry_number_text(arena, number, signed_number);
        else if (type == REG_MULTI_SZ) *query.text = arena.copy("System.String[]");
        else if (type == REG_BINARY || type == REG_NONE) *query.text = arena.copy("System.Byte[]");
        else status = ERROR_INVALID_DATA;
        if (status == ERROR_SUCCESS && !*query.text) status = ERROR_NOT_ENOUGH_MEMORY;
    } else if (status == ERROR_SUCCESS && query.values && type == REG_MULTI_SZ) {
        ah_value *head = nullptr, **tail = &head;
        for (const wchar_t *p = text; *p && !arena.failed; p += ah_wlen(p) + 1) {
            ah_value *item = arena.make<ah_value>(); if (!item) break;
            item->data = arena.utf8(p); item->size = ah_len(item->data); *tail = item; tail = &item->next;
        }
        *query.values = head;
    } else if (status == ERROR_SUCCESS) status = ERROR_INVALID_DATA;
    if (status == ERROR_SUCCESS && query.valid) *query.valid = true;
    if (arena.failed) status = ERROR_NOT_ENOUGH_MEMORY;
    ah_free(expanded); ah_free(data); return status;
}

static bool ah_registry_wmi_strategy(ah_graph &g, ah_object *o, const ah_registry_wmi_query *queries, size_t count, const char **failure) {
    ah_wmi_connection connection(g, o);
    if (!connection.services) { *failure = ah_registry_wmi_reason(g.arena, connection.status); return false; }
    ah_bstr path(connection.automation, L"StdRegProv"); IWbemClassObject *provider = nullptr;
    if (!path.value || FAILED(connection.services->GetObject(path.value, 0, nullptr, &provider, nullptr)) || !provider) { *failure = "WMI StdRegProv unavailable"; return false; }
    bool complete = true;
    for (size_t i = 0; i < count && !g.arena.failed; ++i) {
        ah_registry_wmi_query query = queries[i]; bool exists = false;
        if (!ah_wmi_registry_key(connection, provider, query.path, query.name, &query.type, &exists, failure)) { if (!*failure) *failure = "WMI registry key enumeration failed"; complete = false; break; }
        if (!exists) continue;
        if (queries[i].values && query.type != queries[i].type) { *failure = "WMI registry value type mismatch"; complete = false; break; }
        bool readable = false;
        bool present = ah_registry_wmi_read(connection, g.arena, provider, query, &readable);

        if (!readable || !present) { *failure = "WMI registry value query failed"; complete = false; break; }
    }
    provider->Release(); return complete && !g.arena.failed;
}

static bool ah_registry_remote_strategy(ah_graph &g, ah_object *o, const ah_registry_wmi_query *queries, size_t count, const char **failure) {
    const char *host_name = ah_api_hostname(g, o);
    if (!ah_tcp_open(host_name, 445)) { *failure = "RemoteRegistry port 445 unavailable"; return false; }
    wchar_t *host = ah_wide(host_name); HKEY root = nullptr;
    LONG status = host ? ADVAPI32$RegConnectRegistryW(host, HKEY_LOCAL_MACHINE, &root) : ERROR_NOT_ENOUGH_MEMORY;
    ah_free(host);
    if (status != ERROR_SUCCESS) { *failure = ah_win32_failure(g.arena, "RegConnectRegistry", status); return false; }
    const wchar_t *failed_key = nullptr;
    for (size_t i = 0; i < count && status == ERROR_SUCCESS && !g.arena.failed; ++i) {
        HKEY key = nullptr;
        failed_key = queries[i].path;
        status = ADVAPI32$RegOpenKeyExW(root, queries[i].path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
        if (status == ERROR_SUCCESS) status = ah_registry_query_value(g.arena, key, queries[i]);
        if (key) ADVAPI32$RegCloseKey(key);
    }
    ADVAPI32$RegCloseKey(root);
    if (status != ERROR_SUCCESS) { *failure = ah_registry_key_reason(g.arena, ah_upper(g.arena, host_name), failed_key, status); return false; }
    return !g.arena.failed;
}

static void ah_copy_ntlm_values(ah_object *destination, const ah_object &source) {
    destination->lm_level = source.lm_level; destination->lm_level_valid = source.lm_level_valid;
    destination->use_machine_id = source.use_machine_id; destination->use_machine_id_valid = source.use_machine_id_valid;
    destination->min_client = source.min_client; destination->min_client_valid = source.min_client_valid;
    destination->min_server = source.min_server; destination->min_server_valid = source.min_server_valid;
    destination->restrict_sending = source.restrict_sending; destination->restrict_sending_valid = source.restrict_sending_valid;
    destination->restrict_receiving = source.restrict_receiving; destination->restrict_receiving_valid = source.restrict_receiving_valid;
    destination->ntlm_require_signing = source.ntlm_require_signing; destination->ntlm_require_signing_valid = source.ntlm_require_signing_valid;
    destination->enable_signing = source.enable_signing; destination->enable_signing_valid = source.enable_signing_valid;
    destination->client_allowed_servers = source.client_allowed_servers; destination->client_allowed_servers_valid = source.client_allowed_servers_valid;
}
static void ah_ntlm_queries(ah_object &value, ah_registry_wmi_query (&queries)[9]) {
    queries[0] = {L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"ClientAllowedNTLMServers", REG_MULTI_SZ, nullptr, &value.client_allowed_servers, nullptr, &value.client_allowed_servers_valid};
    queries[1] = {L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"NtlmMinClientSec", REG_DWORD, &value.min_client, nullptr, nullptr, &value.min_client_valid};
    queries[2] = {L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"NtlmMinServerSec", REG_DWORD, &value.min_server, nullptr, nullptr, &value.min_server_valid};
    queries[3] = {L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"RestrictReceivingNTLMTraffic", REG_DWORD, &value.restrict_receiving, nullptr, nullptr, &value.restrict_receiving_valid};
    queries[4] = {L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0", L"RestrictSendingNTLMTraffic", REG_DWORD, &value.restrict_sending, nullptr, nullptr, &value.restrict_sending_valid};
    queries[5] = {L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\", L"LMCompatibilityLevel", REG_DWORD, &value.lm_level, nullptr, nullptr, &value.lm_level_valid};
    queries[6] = {L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\", L"UseMachineId", REG_DWORD, &value.use_machine_id, nullptr, nullptr, &value.use_machine_id_valid};
    queries[7] = {L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"EnableSecuritySignature", REG_DWORD, &value.enable_signing, nullptr, nullptr, &value.enable_signing_valid};
    queries[8] = {L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", L"RequireSecuritySignature", REG_DWORD, &value.ntlm_require_signing, nullptr, nullptr, &value.ntlm_require_signing_valid};
}
static void ah_collect_ntlm_registry_strategy(ah_graph &g, ah_object *o) {
    o->ntlm_registry_requested = true;
    ah_object target = *o; target.canonical_api_name = true;
    ah_object candidate = {}; ah_registry_wmi_query queries[9]; ah_ntlm_queries(candidate, queries);
    const char *wmi_failure = nullptr, *remote_failure = nullptr;
    bool collected = ah_registry_wmi_strategy(g, &target, queries, 9, &wmi_failure);
    if (!collected && !g.arena.failed) {
        candidate = {}; ah_ntlm_queries(candidate, queries);
        collected = ah_registry_remote_strategy(g, &target, queries, 9, &remote_failure);
    }
    ah_object tracked = *o; tracked.id = nullptr;
    if (wmi_failure) ah_track_call(g, &tracked, "ReadRegistrySettings - DotNetWmiRegistryStrategy", wmi_failure);
    if (remote_failure) ah_track_call(g, &tracked, "ReadRegistrySettings - RemoteRegistryStrategy", remote_failure);
    if (collected) ah_track_call(g, &tracked, remote_failure || wmi_failure ? "ReadRegistrySettings - RemoteRegistryStrategy" : "ReadRegistrySettings - DotNetWmiRegistryStrategy", "Success");
    o->ntlm_registry_collected = collected;
    if (collected) { ah_copy_ntlm_values(o, candidate); o->ntlm_registry_failure = nullptr; }
    else o->ntlm_registry_failure = ah_registry_strategy_reason(g.arena, wmi_failure, remote_failure);
}
static void ah_collect_azure_registry_strategy(ah_graph &g, ah_object *o) {
    o->azure_registry_requested = true;
    char *value = nullptr; bool valid = false;
    ah_registry_wmi_query query = {L"SOFTWARE\\Microsoft\\Windows Azure", L"VmId", REG_SZ, nullptr, nullptr, &value, &valid};
    const char *wmi_failure = nullptr, *remote_failure = nullptr;
    bool collected = ah_registry_wmi_strategy(g, o, &query, 1, &wmi_failure);
    if (!collected && !g.arena.failed) { value = nullptr; valid = false; collected = ah_registry_remote_strategy(g, o, &query, 1, &remote_failure); }
    ah_object tracked = *o; tracked.id = nullptr;
    if (wmi_failure) ah_track_call(g, &tracked, "ReadAzureRegistryData - DotNetWmiRegistryStrategy", wmi_failure);
    if (remote_failure) ah_track_call(g, &tracked, "ReadAzureRegistryData - RemoteRegistryStrategy", remote_failure);
    if (collected) ah_track_call(g, &tracked, wmi_failure ? "ReadAzureRegistryData - RemoteRegistryStrategy" : "ReadAzureRegistryData - DotNetWmiRegistryStrategy", "Success");
    o->azure_registry_collected = collected;
    if (!collected) { o->azure_registry_failure = ah_registry_strategy_reason(g.arena, wmi_failure, remote_failure); return; }
    o->azure_registry_failure = nullptr; o->azure_vm_id = nullptr;
    if (value) {
        const char *trimmed = ah_trim_text(g.arena, value);
        if (trimmed) {
            wchar_t *wide = ah_wide(trimmed);
            int length = wide ? KERNEL32$LCMapStringW(LOCALE_INVARIANT, LCMAP_LOWERCASE, wide, -1, nullptr, 0) : 0;
            wchar_t *lower = length > 0 ? ah_alloc<wchar_t>(static_cast<size_t>(length) * sizeof(wchar_t)) : nullptr;
            if (lower && KERNEL32$LCMapStringW(LOCALE_INVARIANT, LCMAP_LOWERCASE, wide, -1, lower, length)) o->azure_vm_id = g.arena.utf8(lower);
            else g.arena.failed = true;
            ah_free(wide); ah_free(lower);
        }
    }
}
