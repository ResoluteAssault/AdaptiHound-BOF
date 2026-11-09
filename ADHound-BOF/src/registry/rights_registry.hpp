#pragma once
static const char *ah_cached_machine_sid(const char *);
static void ah_cache_machine_sid(const char *,const char *);
#include "../../../common/core/native_api.hpp"

static LONG ah_registry_dword_status(ah_object *o, const wchar_t *path, const wchar_t *name, uint32_t *out, HKEY connected_root = nullptr);
static LONG ah_registry_binary_status(ah_arena &arena, ah_object *o, const wchar_t *path, const wchar_t *name, ah_value **out, HKEY connected_root = nullptr);
static bool ah_tcp_open(const char *host, uint16_t port);

static char *ah_sid_from_psid(ah_arena &arena, PSID sid);

static void ah_add_session(ah_arena &arena, ah_session_info **list, const char *sid, const char *name, uint32_t time, uint32_t idle, SID_NAME_USE usage);
static void ah_session_ref(ah_graph &g, ah_buffer &b, const char *sid, SID_NAME_USE usage, ah_object *computer = nullptr);

static const char *ah_win32_failure(ah_arena &arena, const char *operation, ULONG status);
#include "../host/reference_status.hpp"
#include "ca_registry_connection.hpp"
static const char *ah_local_member_id(ah_graph &g, ah_object *computer, const char *sid, SID_NAME_USE usage, const char **kind);
static void ah_track_call(ah_graph &, ah_object *, const char *, const char *, const char *computer_name = nullptr);
static void ah_track_resolved_call(ah_graph &, const char *, const char *, const char *, const char *);

static void ah_local_names_result(ah_graph &g, ah_buffer &b, ah_object *o, ah_session_info *members);

static NTSTATUS ah_collect_machine_sid(ah_graph &g, ah_object *o, LSA_HANDLE policy) {
    if (o->machine_sid) return 0;
    if(const char *cached=ah_cached_machine_sid(o->id)){o->machine_sid=const_cast<char *>(cached);return 0;}
    // The caller owns the policy: use the same RPC context for SID, enumeration and lookup.
    ah_native_library advapi(L"advapi32.dll");
    auto query = advapi.find<decltype(&LsaQueryInformationPolicy)>("LsaQueryInformationPolicy");
    POLICY_ACCOUNT_DOMAIN_INFO *information = nullptr;
    NTSTATUS status = query ? query(policy, PolicyAccountDomainInformation, reinterpret_cast<void **>(&information)) : static_cast<NTSTATUS>(0xc000007aU);
    if (!status && information)
        o->machine_sid = ah_sid_from_psid(g.arena, information->DomainSid);
    if (information) ADVAPI32$LsaFreeMemory(information);
    if(o->machine_sid)ah_cache_machine_sid(o->id,o->machine_sid);
    if (!status && !o->machine_sid) status = static_cast<NTSTATUS>(g.arena.failed ? 0xc0000017U : 0xc0000078U);
    return status;
}

static void ah_collect_user_rights(ah_graph &g, ah_object *o) {
    wchar_t *host = ah_wide(o->text("dNSHostName"));
    if (!host) return;
    LSA_UNICODE_STRING server = {static_cast<USHORT>(ah_wlen(host) * sizeof(wchar_t)), static_cast<USHORT>(ah_wlen(host) * sizeof(wchar_t)), host};
    LSA_OBJECT_ATTRIBUTES attributes = {}; attributes.Length = sizeof(attributes);
    LSA_HANDLE policy = nullptr;
    NTSTATUS status = ADVAPI32$LsaOpenPolicy(&server, &attributes, POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES, &policy);
    if (status) { ah_track_call(g, o, "LSAOpenPolicy", ah_ntstatus_name(g.arena, static_cast<ULONG>(status))); if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: LsaOpenPolicy %s: %lu\n", o->text("dNSHostName"), static_cast<ULONG>(status)); } ah_free(host); return; }
    status = ah_collect_machine_sid(g, o, policy);
    if (status) { const char *reason = ah_ntstatus_name(g.arena, static_cast<ULONG>(status)); ah_track_call(g, o, "LSAGetMachineSID", reason); if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: LSAGetMachineSID %s: %s\n", o->text("dNSHostName"), reason); } ADVAPI32$LsaClose(policy); ah_free(host); return; }
    ah_local_group_info *right = g.arena.make<ah_local_group_info>();
    if (!right) { ADVAPI32$LsaClose(policy); ah_free(host); return; }
    right->name = g.arena.copy("SeRemoteInteractiveLogonRight");
    right->next = o->user_rights; o->user_rights = right;
    USHORT privilege_length = static_cast<USHORT>(ah_wlen(L"SeRemoteInteractiveLogonRight") * sizeof(wchar_t));
    LSA_UNICODE_STRING privilege = {privilege_length, privilege_length, const_cast<wchar_t *>(L"SeRemoteInteractiveLogonRight")};
    LSA_ENUMERATION_INFORMATION *accounts = nullptr; ULONG count = 0;
    status = ADVAPI32$LsaEnumerateAccountsWithUserRight(policy, &privilege, reinterpret_cast<void **>(&accounts), &count);
    const char *operation = "LSAEnumerateAccountsWithUserRight";
    if (status == 0 || static_cast<ULONG>(status) == 0x8000001aU) {
        right->collected = static_cast<ULONG>(status) == 0x8000001aU || count == 0;
        if (!right->collected && accounts && count <= 1000000) {
            PSID *sids = static_cast<PSID *>(g.arena.alloc(sizeof(PSID) * static_cast<size_t>(count)));
            ah_native_library advapi(L"advapi32.dll");
            auto lookup = advapi.find<decltype(&LsaLookupSids)>("LsaLookupSids");
            LSA_REFERENCED_DOMAIN_LIST *domains = nullptr; LSA_TRANSLATED_NAME *names = nullptr;
            operation = "LSALookupSids";
            if (sids && lookup) {
                for (ULONG i = 0; i < count; ++i) sids[i] = accounts[i].Sid;
                status = lookup(policy, count, sids, &domains, &names);
                right->collected = (status == 0 || static_cast<ULONG>(status) == 0x107U) && names;
                if (right->collected) for (ULONG i = 0; i < count; ++i) {
                    char *sid = ah_sid_from_psid(g.arena, accounts[i].Sid); if (!sid) continue;
                    const char *kind = nullptr;
                    if (!ah_local_member_id(g, o, sid, names[i].Use, &kind)) continue;
                    char *translated = nullptr;
                    if (names[i].Name.Buffer && names[i].Name.Length % sizeof(wchar_t) == 0 && names[i].Use != SidTypeUnknown && names[i].Use != SidTypeInvalid && names[i].Use != SidTypeDomain) {
                        size_t n = names[i].Name.Length / sizeof(wchar_t);
                        wchar_t *copy = ah_alloc<wchar_t>((n + 1) * sizeof(wchar_t));
                        if (copy) { for (size_t j = 0; j < n; ++j) copy[j] = names[i].Name.Buffer[j]; copy[n] = 0; translated = g.arena.utf8(copy); ah_free(copy); }
                    }
                    ah_add_session(g.arena, &right->members, sid, translated ? translated : sid, 0, 0, names[i].Use);
                }
            } else status = static_cast<NTSTATUS>(!sids ? 0xc0000017U : 0xc000007aU);
            if (!right->collected && (status == 0 || static_cast<ULONG>(status) == 0x107U)) status = static_cast<NTSTATUS>(0xc000000dU);
            if (names) ADVAPI32$LsaFreeMemory(names);
            if (domains) ADVAPI32$LsaFreeMemory(domains);
        } else if (!right->collected) status = static_cast<NTSTATUS>(0xc000000dU);
    }
    const char *status_name = ah_ntstatus_name(g.arena, static_cast<ULONG>(status));
    if (!right->collected) right->failure_reason = ah_concat(g.arena, operation, " returned ", status_name);
    ah_track_call(g, o, operation, right->collected ? "Success" : status_name);
    if (accounts) ADVAPI32$LsaFreeMemory(accounts);
    ADVAPI32$LsaClose(policy); ah_free(host);
}

static void ah_user_rights_result(ah_graph &g, ah_buffer &b, ah_object *o) {
    AH_TEXT(&b, "["); bool first = true;
    for (ah_local_group_info *right = o->user_rights; right; right = right->next) {
        if (!first) { AH_TEXT(&b, ","); } first = false;
        AH_TEXT(&b, "{\"Privilege\":"); ah_string(b, right->name);
        AH_TEXT(&b, ",\"Results\":["); bool member_first = true;
        for (ah_session_info *member = right->members; member; member = member->next) {
            if (!member_first) { AH_TEXT(&b, ","); }
            member_first = false; ah_session_ref(g, b, member->sid, member->usage, o);
        }
        AH_TEXT(&b, "],\"LocalNames\":"); ah_local_names_result(g, b, o, right->members); AH_TEXT(&b, ",\"Collected\":"); if (right->collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
        AH_TEXT(&b, ",\"FailureReason\":");
        if (!right->collected) ah_string(b, right->failure_reason ? right->failure_reason : "LSA query failed"); else AH_TEXT(&b, "null");
        AH_TEXT(&b, "}");
    }
    AH_TEXT(&b, "]");
}

struct ah_registry_wmi_query {
    const wchar_t *path, *name;
    DWORD type;
    uint32_t *number;
    ah_value **values;
    char **text;
    bool *valid;
    bool *collected = nullptr;
    const char **failure = nullptr;
};

#include "registry_value.hpp"

static void ah_registry_wmi_fallback(ah_graph &g, ah_object *o, const ah_registry_wmi_query *queries, size_t count);

static bool ah_registry_status_collected(LONG status) {
    return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
}

static const char *ah_ca_registry_reason(ah_graph &g, ah_object *o, const char *operation, LONG status) {
    if (status == ERROR_TIMEOUT || status == RPC_S_CALL_CANCELLED)
        return ah_concat(g.arena,"Failed to connect to registry on ",o->text("dNSHostName"),": Timeout after 10000 ms");
    return ah_registry_status_reason(g.arena,operation,status);
}

static void ah_track_ca_registry(ah_graph &g, ah_object *o) {
    if (!ah_track_computer_calls) return;
    const char *name = o->text("dNSHostName");
    ah_object *host = o->registry_host ? o->registry_host : g.hosts.find(name);
    const char *host_id = host ? host->id : nullptr;

    ah_track_resolved_call(g, name, host_id, "ProcessRegistryEnrollmentPermissions", o->ca_security_collected ? "Success" : o->ca_security_failure ? o->ca_security_failure : "CARegistryQueryFailed");
    ah_track_resolved_call(g, name, host_id, "ProcessEAPermissions", o->enrollment_agent_collected ? "Success" : o->enrollment_agent_failure ? o->enrollment_agent_failure : "CARegistryQueryFailed");
    ah_track_resolved_call(g, name, host_id, "IsUserSpecifiesSanEnabled", o->san_collected ? "Success" : o->san_failure ? o->san_failure : "CARegistryQueryFailed");
    ah_track_resolved_call(g, name, host_id, "IsRoleSeparationEnabled", o->role_separation_collected ? "Success" : o->role_separation_failure ? o->role_separation_failure : "CARegistryQueryFailed");
}

static void ah_collect_ca_registry(ah_graph &g, ah_object *o) {
    o->ca_registry_requested = true;
    if (!*o->text("dNSHostName")) {
        o->ca_security_failure = o->enrollment_agent_failure = o->san_failure = o->role_separation_failure = "HostNameUnavailable";
        ah_track_ca_registry(g, o);
        return;
    }
    char *base_name = ah_concat(g.arena, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\", o->text("cn", o->text("name")));
    wchar_t *base = ah_wide(base_name);
    wchar_t *policy = ah_wide(ah_concat(g.arena, base_name, "\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy"));
    if (!base || !policy) {
        o->ca_security_failure = o->enrollment_agent_failure = o->san_failure = o->role_separation_failure = "OutOfMemory";
        ah_free(base); ah_free(policy); ah_track_ca_registry(g, o); return;
    }

    ah_ca_registry_connections connections(o->text("dNSHostName"));
    HKEY root = nullptr;
    uint32_t role = 0, edit = 0;
    LONG status = connections.connect(&root);
    if (status == ERROR_SUCCESS) status = ah_registry_dword_status(o, policy, L"EditFlags", &edit, root);
    o->san_valid = status == ERROR_SUCCESS; o->san_collected = ah_registry_status_collected(status);
    if (!o->san_collected) o->san_failure = ah_ca_registry_reason(g,o,"EditFlags",status);
    status = connections.connect(&root);
    if (status == ERROR_SUCCESS) status = ah_registry_binary_status(g.arena, o, base, L"EnrollmentAgentRights", &o->enrollment_agent_rights, root);
    o->enrollment_agent_collected = ah_registry_status_collected(status);
    if (!o->enrollment_agent_collected) o->enrollment_agent_failure = ah_ca_registry_reason(g,o,"EnrollmentAgentRights",status);
    status = connections.connect(&root);
    if (status == ERROR_SUCCESS) status = ah_registry_dword_status(o, base, L"RoleSeparationEnabled", &role, root);
    o->role_separation_valid = status == ERROR_SUCCESS; o->role_separation_collected = ah_registry_status_collected(status);
    if (!o->role_separation_collected) o->role_separation_failure = ah_ca_registry_reason(g,o,"RoleSeparationEnabled",status);
    status = connections.connect(&root);
    if (status == ERROR_SUCCESS) status = ah_registry_binary_status(g.arena, o, base, L"Security", &o->ca_security, root);
    o->ca_security_collected = ah_registry_status_collected(status);
    if (!o->ca_security_collected) o->ca_security_failure = ah_ca_registry_reason(g,o,"CA Security",status);
    o->role_separation_enabled = role == 1; o->san_enabled = (edit & 0x00040000U) != 0;
    ah_track_ca_registry(g, o);
    ah_free(base); ah_free(policy);
}
