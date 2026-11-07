#pragma once
#include "../../../common/core/native_api.hpp"

static const GUID AH_CLSID_WBEM_LOCATOR = {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
static const GUID AH_IID_WBEM_LOCATOR = {0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};

class ah_automation final {
    ah_native_library library;
public:
    using alloc_type = BSTR (WINAPI *)(const OLECHAR *);
    using free_type = void (WINAPI *)(BSTR);
    using clear_type = HRESULT (WINAPI *)(VARIANTARG *);
    alloc_type alloc;
    free_type free;
    clear_type clear;
    ah_automation() : library(L"oleaut32.dll"), alloc(library.find<alloc_type>("SysAllocString")), free(library.find<free_type>("SysFreeString")), clear(library.find<clear_type>("VariantClear")) {}
    bool valid() const { return alloc && free && clear; }
};
class ah_bstr final {
    ah_automation &automation;
public:
    BSTR value;
    ah_bstr(ah_automation &api, const wchar_t *source) : automation(api), value(api.alloc(source)) {}
    ~ah_bstr() { if (value) automation.free(value); }
    ah_bstr(const ah_bstr &) = delete;
    ah_bstr &operator=(const ah_bstr &) = delete;
};

static bool ah_tcp_open(const char *host, uint16_t port);

static bool ah_current_machine_fqdn(ah_arena &arena, const char *host) {
    ah_native_library kernel(L"kernel32.dll");
    auto name = kernel.find<decltype(&GetComputerNameExW)>("GetComputerNameExW");
    wchar_t value[512]; DWORD length = sizeof(value) / sizeof(value[0]);
    return name && name(ComputerNameDnsFullyQualified, value, &length) && ah_eq(arena.utf8(value), host);
}

class ah_wmi_connection final {
    ah_native_library ole;
    using uninit_type = void (WINAPI *)();
    using blanket_type = HRESULT (WINAPI *)(IUnknown *, DWORD, DWORD, OLECHAR *, DWORD, DWORD, RPC_AUTH_IDENTITY_HANDLE, DWORD);
    blanket_type blanket = nullptr;
    uninit_type uninitialize = nullptr;
    bool initialized = false;
    DWORD authentication = RPC_C_AUTHN_GSS_KERBEROS;
    IWbemLocator *locator = nullptr;
public:
    ah_automation automation;
    IWbemServices *services = nullptr;
    HRESULT status = E_FAIL;
    ah_wmi_connection(ah_graph &g, ah_object *o) : ole(L"ole32.dll") {
        if (!ah_tcp_open(ah_api_hostname(g, o), 135)) { status = HRESULT_FROM_WIN32(RPC_S_SERVER_UNAVAILABLE); return; }
        const bool local = ah_current_machine_fqdn(g.arena, ah_api_hostname(g, o));
        if (local) authentication = RPC_C_AUTHN_WINNT;
        if (!automation.valid()) return;
        auto initialize = ole.find<decltype(&CoInitializeEx)>("CoInitializeEx");
        auto security_initialize = ole.find<decltype(&CoInitializeSecurity)>("CoInitializeSecurity");
        auto create = ole.find<decltype(&CoCreateInstance)>("CoCreateInstance");
        uninitialize = ole.find<uninit_type>("CoUninitialize");
        blanket = ole.find<blanket_type>("CoSetProxyBlanket");
        if (!initialize || !security_initialize || !create || !uninitialize || !blanket) return;
        status = initialize(nullptr, COINIT_MULTITHREADED); initialized = SUCCEEDED(status);
        if (FAILED(status) && status != RPC_E_CHANGED_MODE) return;
        status = security_initialize(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
        if (FAILED(status) && status != RPC_E_TOO_LATE) return;
        status = create(AH_CLSID_WBEM_LOCATOR, nullptr, CLSCTX_INPROC_SERVER, AH_IID_WBEM_LOCATOR, reinterpret_cast<void **>(&locator));
        if (FAILED(status) || !locator) return;
        wchar_t *wide = ah_wide(local ? "root\\cimv2" : ah_concat(g.arena, "\\\\", ah_api_hostname(g, o), "\\root\\cimv2"));
        if (!wide) { status = E_OUTOFMEMORY; return; }
        ah_bstr location(automation, wide); ah_free(wide);
        if (!location.value) { status = E_OUTOFMEMORY; return; }
        wchar_t *authority_text = ah_wide(ah_concat(g.arena, ah_concat(g.arena, "kerberos:", g.object_domain(o)), "\\", ah_api_hostname(g, o)));
        if (!authority_text) { status = E_OUTOFMEMORY; return; }
        ah_bstr authority(automation, authority_text); ah_free(authority_text);
        if (!authority.value) { status = E_OUTOFMEMORY; return; }
        status = locator->ConnectServer(location.value, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT, local ? nullptr : authority.value, nullptr, &services);
        if (FAILED(status) || !services) return;
        status = secure(services);
        if (FAILED(status)) { services->Release(); services = nullptr; }
    }
    HRESULT secure(IUnknown *proxy) const {
        return blanket ? blanket(proxy, authentication, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING) : E_FAIL;
    }
    ~ah_wmi_connection() {
        if (services) services->Release();
        if (locator) locator->Release();
        if (initialized && uninitialize) uninitialize();
    }
    ah_wmi_connection(const ah_wmi_connection &) = delete;
    ah_wmi_connection &operator=(const ah_wmi_connection &) = delete;
};

static void ah_collect_rdp_sessions(ah_graph &g, ah_object *o, const wchar_t *dc) {
    wchar_t *host = ah_wide(o->text("dNSHostName"));
    if (!host) return;
    ah_native_library wts(L"wtsapi32.dll");
    auto open = wts.find<decltype(&WTSOpenServerW)>("WTSOpenServerW");
    auto enumerate = wts.find<decltype(&WTSEnumerateSessionsExW)>("WTSEnumerateSessionsExW");
    auto release = wts.find<decltype(&WTSFreeMemoryExW)>("WTSFreeMemoryExW");
    auto close = wts.find<decltype(&WTSCloseServer)>("WTSCloseServer");
    if (!open || !enumerate || !release || !close) { if (!o->privileged_collected) o->privileged_failure_reason = "WTSApiUnavailable"; ah_free(host); return; }
    HANDLE server = open(host);
    if (!server || server == INVALID_HANDLE_VALUE) { if (!o->privileged_collected) o->privileged_failure_reason = ah_win32_failure(g.arena, "WTSOpenServer", KERNEL32$GetLastError()); ah_free(host); return; }
    WTS_SESSION_INFO_1W *sessions = nullptr; DWORD count = 0, level = 1;
    if (enumerate(server, &level, 0, &sessions, &count)) {
        o->privileged_collected = true;
        for (DWORD i = 0; i < count && !g.arena.failed; ++i) {
            if (!sessions[i].pUserName || !*sessions[i].pUserName) continue;
            char *sid = ah_user_sid(g, o, sessions[i].pUserName, dc, sessions[i].pDomainName);
            char *name = sid ? ah_concat(g.arena, g.arena.utf8(sessions[i].pUserName), "@", sessions[i].pDomainName ? g.arena.utf8(sessions[i].pDomainName) : g.domain) : nullptr;
            ah_add_computer_session(g.arena, &o->privileged_sessions, o->id, sid, name);
        }
    }
    else if (!o->privileged_collected) o->privileged_failure_reason = ah_win32_failure(g.arena, "WTSEnumerateSessionsEx", KERNEL32$GetLastError());
    if (sessions) release(WTSTypeSessionInfoLevel1, sessions, count);
    close(server); ah_free(host);
}

static wchar_t *ah_wmi_string(ah_automation &api, IWbemClassObject *object, const wchar_t *name) {
    VARIANT value = {}; wchar_t *result = nullptr;
    if (SUCCEEDED(object->Get(name, 0, &value, nullptr, nullptr)) && value.vt == VT_BSTR && value.bstrVal) {
        size_t length = ah_wlen(value.bstrVal) + 1;
        result = ah_alloc<wchar_t>(length * sizeof(wchar_t));
        if (result) for (size_t i = 0; i < length; ++i) result[i] = value.bstrVal[i];
    }
    api.clear(&value);
    return result;
}

static wchar_t *ah_wmi_path_key(const wchar_t *path, const wchar_t *key) {
    size_t key_length = ah_wlen(key);
    for (const wchar_t *p = path; p && *p; ++p) {
        bool boundary = p == path || p[-1] == '.' || p[-1] == ',' || p[-1] == ' ';
        if (!boundary) continue;
        size_t index = 0;
        while (index < key_length && p[index] == key[index]) ++index;
        if (index != key_length || p[index] != '=') continue;
        p += index + 1; if (*p != '"') continue;
        ++p;
        wchar_t *value = ah_alloc<wchar_t>((ah_wlen(p) + 1) * sizeof(wchar_t));
        if (!value) return nullptr;
        size_t length = 0;
        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) ++p;
            value[length++] = *p++;
        }
        if (*p != '"') { ah_free(value); return nullptr; }
        value[length] = 0; return value;
    }
    return nullptr;
}

static void ah_wmi_process(ah_automation &api, ah_graph &g, ah_object *o, IWbemClassObject *object, IWbemServices *services, const wchar_t *dc, bool owner) {
    if (owner) {
        VARIANT id = {};
        if (SUCCEEDED(object->Get(L"ProcessId", 0, &id, nullptr, nullptr)) && (id.vt == VT_I4 || id.vt == VT_UI4)) {
            wchar_t path[128]; MSVCRT$_snwprintf(path, 128, L"Win32_Process.Handle=\"%u\"", id.uintVal);
            ah_bstr object_path(api, path), method(api, L"GetOwner");
            IWbemClassObject *result = nullptr;
            if (object_path.value && method.value && SUCCEEDED(services->ExecMethod(object_path.value, method.value, 0, nullptr, nullptr, &result, nullptr)) && result) {
                wchar_t *user = ah_wmi_string(api, result, L"User"), *domain = ah_wmi_string(api, result, L"Domain");
                if (user && *user && domain && *domain) {
                    char *sid = ah_user_sid(g, o, user, dc, domain);
                    ah_add_computer_session(g.arena, &o->privileged_sessions, o->id, sid, g.arena.utf8(user));
                }
                ah_free(user); ah_free(domain); result->Release();
            }
        }
        api.clear(&id); return;
    }
    wchar_t *account = ah_wmi_string(api, object, L"Antecedent");
    if (!account) return;
    wchar_t *user = ah_wmi_path_key(account, L"Name"), *domain = ah_wmi_path_key(account, L"Domain");
    if (user && domain && *domain) {
        char *sid = ah_user_sid(g, o, user, dc, domain);
        ah_add_computer_session(g.arena, &o->privileged_sessions, o->id, sid, g.arena.utf8(user));
    }
    ah_free(user); ah_free(domain); ah_free(account);
}

static void ah_collect_wmi_sessions(ah_graph &g, ah_object *o, const wchar_t *dc) {
    ah_wmi_connection connection(g, o);
    if (!connection.services) {
        if (!o->privileged_collected) o->privileged_failure_reason = ah_win32_failure(g.arena, "WMIConnectServer", static_cast<ULONG>(connection.status));
        return;
    }
    ah_automation &api = connection.automation;
    const wchar_t *queries[] = {L"SELECT Antecedent FROM Win32_LoggedOnUser", L"SELECT ProcessId FROM Win32_Process WHERE Name='wsmprovhost.exe' OR Name='dllhost.exe'"};
    for (unsigned int i = 0; i < 2 && !g.arena.failed; ++i) {
        ah_bstr language(api, L"WQL"), query(api, queries[i]); IEnumWbemClassObject *enumerator = nullptr;
        HRESULT status = language.value && query.value ? connection.services->ExecQuery(language.value, query.value, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &enumerator) : E_OUTOFMEMORY;
        if (FAILED(status) || !enumerator) {
            if (!o->privileged_collected) o->privileged_failure_reason = ah_win32_failure(g.arena, "WMIExecQuery", static_cast<ULONG>(status));
            continue;
        }
        status = connection.secure(enumerator);
        if (FAILED(status)) {
            if (!o->privileged_collected) o->privileged_failure_reason = ah_win32_failure(g.arena, "WMIEnumeratorProxy", static_cast<ULONG>(status));
            enumerator->Release(); continue;
        }
        for (;;) {
            IWbemClassObject *object = nullptr; ULONG count = 0;
            HRESULT next = enumerator->Next(5000, 1, &object, &count);
            if (FAILED(next) || next == WBEM_S_TIMEDOUT) {
                if (!o->privileged_collected) o->privileged_failure_reason = ah_win32_failure(g.arena, "WMIEnumeration", static_cast<ULONG>(next));
                if (object) object->Release();
                break;
            }
            o->privileged_collected = true;
            if (!count) { if (object) object->Release(); break; }
            ah_wmi_process(api, g, o, object, connection.services, dc, i != 0); object->Release();
            if (g.arena.failed) break;
        }
        enumerator->Release();
    }
}

static bool ah_registry_query_missing(const ah_registry_wmi_query &query) {
    if (query.valid) return !*query.valid;
    if (query.values) return !*query.values;
    return query.text && !*query.text;
}

static bool ah_wmi_put_string(ah_automation &api, IWbemClassObject *object, const wchar_t *name, const wchar_t *value) {
    ah_bstr string(api, value);
    if (!string.value) return false;
    VARIANT input = {}; input.vt = VT_BSTR; input.bstrVal = string.value;
    return SUCCEEDED(object->Put(name, 0, &input, CIM_STRING));
}

static bool ah_registry_wmi_array(ah_arena &arena, const VARIANT &value, DWORD registry_type, ah_value **result) {
    VARTYPE expected = registry_type == REG_BINARY ? VT_UI1 : VT_BSTR;
    if (!result || value.vt != static_cast<VARTYPE>(VT_ARRAY | expected) || !value.parray) return false;
    ah_native_library automation(L"oleaut32.dll");
    auto dimensions = automation.find<decltype(&SafeArrayGetDim)>("SafeArrayGetDim");
    auto lower = automation.find<decltype(&SafeArrayGetLBound)>("SafeArrayGetLBound");
    auto upper = automation.find<decltype(&SafeArrayGetUBound)>("SafeArrayGetUBound");
    auto access = automation.find<decltype(&SafeArrayAccessData)>("SafeArrayAccessData");
    auto unaccess = automation.find<decltype(&SafeArrayUnaccessData)>("SafeArrayUnaccessData");
    LONG low = 0, high = -1; void *data = nullptr;
    if (!dimensions || !lower || !upper || !access || !unaccess || dimensions(value.parray) != 1 || FAILED(lower(value.parray, 1, &low)) || FAILED(upper(value.parray, 1, &high))) return false;
    if (high < low) { *result = nullptr; return registry_type == REG_MULTI_SZ; }
    if (static_cast<unsigned long long>(static_cast<int64_t>(high) - low) >= 16 * 1024 * 1024 || FAILED(access(value.parray, &data))) return false;
    ah_value *head = nullptr, **tail = &head;
    if (!data) { unaccess(value.parray); return false; }
    if (registry_type == REG_BINARY) {
        ah_value *item = arena.make<ah_value>(); size_t size = static_cast<size_t>(static_cast<int64_t>(high) - low) + 1;
        if (item) { item->data = arena.copy(static_cast<const char *>(data), size); item->size = size; head = item; }
    } else {
        BSTR *strings = static_cast<BSTR *>(data);
        for (size_t i = 0, count = static_cast<size_t>(static_cast<int64_t>(high) - low) + 1; i < count && !arena.failed; ++i) {
            ah_value *item = arena.make<ah_value>(); if (!item) break;
            item->data = strings[i] ? arena.utf8(strings[i]) : arena.copy(""); item->size = ah_len(item->data);
            *tail = item; tail = &item->next;
        }
    }
    unaccess(value.parray); *result = head; return !arena.failed;
}

static bool ah_registry_wmi_read(ah_wmi_connection &connection, ah_arena &arena, IWbemClassObject *provider, const ah_registry_wmi_query &query, bool *readable) {
    ah_automation &api = connection.automation;
    const wchar_t *method_name = query.type == REG_DWORD ? L"GetDWORDValue" : query.type == REG_BINARY ? L"GetBinaryValue" : query.type == REG_MULTI_SZ ? L"GetMultiStringValue" : query.type == REG_EXPAND_SZ ? L"GetExpandedStringValue" : query.type == REG_QWORD ? L"GetQWORDValue" : L"GetStringValue";
    IWbemClassObject *signature = nullptr, *input = nullptr, *output = nullptr;
    if (FAILED(provider->GetMethod(method_name, 0, &signature, nullptr)) || !signature) return false;
    HRESULT status = signature->SpawnInstance(0, &input); signature->Release();
    if (FAILED(status) || !input) return false;
    VARIANT hive = {}; hive.vt = VT_I4; hive.lVal = static_cast<LONG>(0x80000002U);
    bool ready = SUCCEEDED(input->Put(L"hDefKey", 0, &hive, CIM_UINT32)) && ah_wmi_put_string(api, input, L"sSubKeyName", query.path) && ah_wmi_put_string(api, input, L"sValueName", query.name);
    ah_bstr object_path(api, L"StdRegProv"), method(api, method_name);
    IWbemCallResult *call = nullptr;
    if (ready && object_path.value && method.value) {
        status = connection.services->ExecMethod(object_path.value, method.value, WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, input, nullptr, &call);
        if (SUCCEEDED(status) && call) status = connection.secure(call);
        if (SUCCEEDED(status) && call) status = call->GetResultObject(5000, &output);
    }
    input->Release(); if (call) call->Release();
    if (FAILED(status) || status == WBEM_S_TIMEDOUT || !output) { if (output) output->Release(); return false; }
    VARIANT code = {}, value = {};
    bool returned = SUCCEEDED(output->Get(L"ReturnValue", 0, &code, nullptr, nullptr)) && (code.vt == VT_I4 || code.vt == VT_UI4);
    if (readable) *readable = returned && (code.ulVal == ERROR_SUCCESS || code.ulVal == ERROR_FILE_NOT_FOUND || code.ulVal == ERROR_PATH_NOT_FOUND);
    bool ok = returned && code.ulVal == ERROR_SUCCESS;
    if (ok) ok = SUCCEEDED(output->Get(query.type == REG_DWORD || query.type == REG_BINARY || query.type == REG_QWORD ? L"uValue" : L"sValue", 0, &value, nullptr, nullptr));
    if (ok && (query.number || query.text)) ok = ah_registry_variant_value(arena, query, value);
    else if (ok) ok = ah_registry_wmi_array(arena, value, query.type, query.values);
    if (readable && returned && code.ulVal == ERROR_SUCCESS && !ok) *readable = false;
    ULONG failure_code = returned ? (code.ulVal == ERROR_SUCCESS && !ok ? ERROR_INVALID_DATA : code.ulVal) : static_cast<ULONG>(status);
    api.clear(&code); api.clear(&value); output->Release();
    if (ok && query.valid) *query.valid = true;
    if (query.collected && readable && *readable) *query.collected = true;
    if (query.failure && (!readable || !*readable)) *query.failure = ah_win32_failure(arena, "WMI StdRegProv", failure_code);
    return ok;
}

static void ah_registry_wmi_fallback(ah_graph &g, ah_object *o, const ah_registry_wmi_query *queries, size_t count) {
    bool needed = false;
    for (size_t i = 0; i < count; ++i) if (ah_registry_query_missing(queries[i])) needed = true;
    if (!needed || g.arena.failed) return;
    ah_wmi_connection connection(g, o);
    if (!connection.services) return;
    ah_bstr path(connection.automation, L"StdRegProv"); IWbemClassObject *provider = nullptr;
    if (!path.value || FAILED(connection.services->GetObject(path.value, 0, nullptr, &provider, nullptr)) || !provider) return;
    for (size_t i = 0; i < count && !g.arena.failed; ++i) {
        if (!ah_registry_query_missing(queries[i])) continue;
        bool readable = false;
        ah_registry_wmi_read(connection, g.arena, provider, queries[i], &readable);
        if (readable && o->dc_registry_requested) {
            if (ah_weq(queries[i].name, L"CertificateMappingMethods")) o->cert_mapping_collected = true;
            if (ah_weq(queries[i].name, L"StrongCertificateBindingEnforcement")) o->strong_binding_collected = true;
            if (ah_weq(queries[i].name, L"VulnerableChannelAllowList")) o->vulnerable_netlogon_collected = true;
        }
        if (readable && o->ntlm_registry_requested) {
            const wchar_t *ntlm_names[] = {L"LmCompatibilityLevel", L"UseMachineId", L"NtlmMinClientSec", L"NtlmMinServerSec", L"RestrictSendingNTLMTraffic", L"RestrictReceivingNTLMTraffic", L"RequireSecuritySignature", L"EnableSecuritySignature", L"ClientAllowedNTLMServers"};
            for (const wchar_t *name : ntlm_names) if (ah_weq(queries[i].name, name)) o->ntlm_registry_collected = true;
        }
    }
    provider->Release();
}
