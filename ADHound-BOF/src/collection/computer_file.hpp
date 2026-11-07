#pragma once
#include "target_stream.hpp"

static const char *ah_computer_file_ldap_host_sid(ah_graph &graph, LDAP *ld, wchar_t *base, const char *host) {
    const char *end = host; while (*end && *end != '.') ++end;
    char *escaped = ah_filter_escape(graph.arena, host);
    char *sam = ah_concat(graph.arena, graph.arena.copy(host, static_cast<size_t>(end - host)), "$");
    char *escaped_sam = sam ? ah_filter_escape(graph.arena, sam) : nullptr;
    char *filter = escaped && escaped_sam ? ah_concat(graph.arena, ah_concat(graph.arena, "(|(dNSHostName=", escaped, ")(sAMAccountName="), escaped_sam, "))") : nullptr;
    wchar_t *wide = filter ? ah_wide(filter) : nullptr;
    if (!wide) return nullptr;
    wchar_t *attributes[] = {const_cast<wchar_t *>(L"objectSid"), nullptr};
    LDAPMessage *result = nullptr; struct l_timeval timeout = {ah_ldap_query_timeout_seconds, 0};
    ULONG status = ah_ldap_search_retry(ld, base, LDAP_SCOPE_SUBTREE, wide, attributes, 0, nullptr, nullptr, &timeout, 0, &result);
    ah_free(wide); const char *sid = nullptr;
    if (status == LDAP_SUCCESS) {
        LDAPMessage *entry = result ? WLDAP32$ldap_first_entry(ld, result) : nullptr;
        if (entry) {
            struct berval **values = WLDAP32$ldap_get_values_lenW(ld, entry, const_cast<wchar_t *>(L"objectSid"));
            if (values && values[0]) sid = ah_sid(graph.arena, reinterpret_cast<unsigned char *>(values[0]->bv_val), values[0]->bv_len);
            if (values) WLDAP32$ldap_value_free_len(values);
        }
    }
    if (result) WLDAP32$ldap_msgfree(result);
    return sid;
}
static const char *ah_computer_file_host(ah_arena &arena, const char *target) {
    const char *host = target;
    for (const char *p = target; *p; ++p) if (*p == '/') { host = p + 1; break; }
    const char *end = host + ah_len(host);
    if (host < end && host[0] == '[') {
        const char *close = host; while (*close && *close != ']') ++close;
        if (*close == ']') { ++host; end = close; }
    } else {
        const char *colon = nullptr; unsigned int colons = 0;
        for (const char *p = host; p < end; ++p) if (*p == ':') { colon = p; ++colons; }
        if (colons == 1) end = colon;
        if (end > host && end[-1] == '$') --end;
    }
    return end > host ? arena.copy(host, static_cast<size_t>(end - host)) : nullptr;
}
static const char *ah_computer_file_workstation_sid(ah_graph &graph, LDAP *ld, wchar_t *base, const char *host) {
    if (!ah_tcp_open(host, 445)) return nullptr;
    ah_native_library netapi(L"netapi32.dll");
    auto query = netapi.find<decltype(&NetWkstaGetInfo)>("NetWkstaGetInfo");
    if (!query) return nullptr;
    wchar_t *wide = ah_wide(host); WKSTA_INFO_100 *information = nullptr;
    NET_API_STATUS status = wide ? query(wide, 100, reinterpret_cast<LPBYTE *>(&information)) : ERROR_NOT_ENOUGH_MEMORY;
    ah_free(wide); const char *sid = nullptr;
    if (status == NERR_Success && information && information->wki100_computername && *information->wki100_computername) {
        const char *name = graph.arena.utf8(information->wki100_computername);
        const char *domain = information->wki100_langroup && *information->wki100_langroup ? graph.arena.utf8(information->wki100_langroup) : graph.domain;
        if (name && domain) sid = ah_host_account_sid(graph, ah_concat(graph.arena, name, "$"), domain);

        if (!sid && name) sid = ah_computer_file_ldap_host_sid(graph, ld, base, name);
    }
    if (information) NETAPI32$NetApiBufferFree(information);
    return sid;
}
static bool ah_collect_computer_file(ah_directory &directory, LDAP *ld, const ah_profile *profile, wchar_t *base, int methods, unsigned int pages) {
    ah_graph graph(directory, true);
    if (!graph.init(base)) { if(graph.arena.failed)directory.arena.failed=true;return false; }
    const wchar_t *all[] = {L"*", nullptr};
    const wchar_t *selected[256]; size_t count = 0;
    for (const wchar_t *const *attribute = profile->attributes; attribute && *attribute; ++attribute) {
        if (!ah_query_attribute_enabled(*attribute, methods, false)) continue;
        if (count + 1 >= sizeof(selected) / sizeof(selected[0])) { directory.arena.failed = true; return false; }
        selected[count++] = *attribute;
    }
    selected[count] = nullptr;
    const wchar_t *const *attributes = ah_collect_all_properties ? all : selected;
    auto collect_target = [&](const char *target) -> bool {
        if (!target || !*target) return true;
        const char *sid = nullptr;
        if (ah_prefix(target, "S-1-5-21")) sid = target;
        else {
            const char *host = ah_computer_file_host(graph.arena, target);
            wchar_t *wide = host ? ah_wide(host) : nullptr;
            if (host) sid = ah_computer_file_workstation_sid(graph, ld, base, host);
            const bool loopback = host && (ah_eq(host, "127.0.0.1") || ah_eq(host, "::1") || ah_eq(host, "localhost"));
            if (!sid && wide && !loopback) sid = ah_session_host_sid(graph, graph.root, wide);
            ah_free(wide);
            if (!sid && host) sid = ah_computer_file_ldap_host_sid(graph, ld, base, host);
            if (!sid) {
                BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: ComputerFileProducer cannot resolve %s to SID\n", target);
                return true;
            }
            ah_object tracked = {}; tracked.id = const_cast<char *>(sid); tracked.dn = const_cast<char *>(target);
            ah_track_call(graph, &tracked, "ComputerFileProducer - Produce", "Success", target);
        }
        unsigned char binary[68]; size_t binary_size = 0;
        if (!ah_gpo_sid_bytes(sid, binary, binary_size)) { BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: ComputerFileProducer invalid SID %s\n", sid); return true; }
        ah_buffer filter(1024); AH_TEXT(&filter, "(objectSid="); static const char hex[] = "0123456789abcdef";
        for (size_t i = 0; i < binary_size; ++i) { char encoded[] = {'\\', hex[binary[i] >> 4], hex[binary[i] & 15]}; ah_append(&filter, encoded, sizeof(encoded)); }
        AH_TEXT(&filter, ")\0"); wchar_t *wide = filter.failed ? nullptr : ah_wide(filter.data);
        if (!wide) { directory.arena.failed = true; return false; }
        const ah_query query = {L"computerfile", L"", wide, LDAP_SCOPE_SUBTREE, 1};

        bool complete = ah_dataset(directory, ld, &query, base, attributes, 0, pages, false, false, false, true, !*ah_computer_file_path&&!ah_computer_file_inline) != 0;
        ah_free(wide);
        if (!complete && directory.arena.failed) return false;
        return !directory.arena.failed && !graph.arena.failed;
    };
    if (*ah_computer_file_path || ah_computer_file_inline) {
        ah_target_stream source(ah_computer_file_path, ah_computer_file_inline ? ah_computer_file_text : nullptr);
        ah_buffer line(0, 4096);
        while (source.next(line)) if (!collect_target(line.data)) { if(graph.arena.failed)directory.arena.failed=true;return false; }
        if(source.no_memory()||line.failed||graph.arena.failed)directory.arena.failed=true;
        if (source.failed()) BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: cannot read ComputerFile on collecting host: %s", ah_computer_file_path);

        return !directory.arena.failed && !graph.arena.failed;
    }

    const char *targets = ah_computer_targets ? ah_computer_targets : "";
    while (*targets && !directory.arena.failed) {
        const char *end = targets; while (*end && *end != ',') ++end;
        char *raw = graph.arena.copy(targets, static_cast<size_t>(end - targets));
        const char *target = raw ? ah_trim_text(graph.arena, raw) : nullptr;
        targets = *end ? end + 1 : end;
        if (!collect_target(target)) { if(graph.arena.failed)directory.arena.failed=true;return false; }
    }
    if(graph.arena.failed)directory.arena.failed=true;
    return !directory.arena.failed;
}
