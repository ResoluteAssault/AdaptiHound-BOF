#pragma once
#include "../../../common/core/native_api.hpp"
#include <ws2tcpip.h>

static bool ah_gc_user_matches(ah_graph &, const char *, ah_session_info **);
static bool ah_resolve_directory_sid(ah_graph &, const char *, const char **, const char **);
static bool ah_resolve_directory_account_sid(ah_graph &, const char *, const char *, const char **);
static bool ah_cached_host_sid(const char *,const char **);
static void ah_cache_host_sid(const char *,const char *);
static void ah_computer_delay();
static void ah_mark_output_reference(ah_graph &, const char *);

static const char *ah_api_hostname(ah_graph &g, ah_object *o) {
    const char *host = o->text("dNSHostName");
    if (o->canonical_api_name || (!ah_real_dns_name_present && (!ah_real_dns_name || !*ah_real_dns_name)) || !ah_eq(o->kind, "Computer")) return host;
    if (!o->synthesized_dns_name && o->values("dNSHostName")) return host;
    const char *short_name=o->text("sAMAccountName",nullptr);
    size_t length=ah_len(short_name);
    if(short_name)while(length&&short_name[length-1]=='$')--length;
    else {short_name=o->text("cn","UNKNOWN");length=ah_len(short_name);}
    return ah_concat(g.arena,g.arena.copy(short_name,length),".",ah_real_dns_name?ah_real_dns_name:"");
}

#include "session_credentials.hpp"

static char *ah_sid_from_psid(ah_arena &arena, PSID sid) {
    if (!sid) return nullptr;
    const unsigned char *bytes = static_cast<const unsigned char *>(sid);
    if (bytes[0] != 1 || bytes[1] > 15) return nullptr;
    return ah_sid(arena, bytes, 8 + 4 * static_cast<size_t>(bytes[1]));
}

static void ah_track_call(ah_graph &g, ah_object *o, const char *task, const char *status, const char *computer_name) {
    if (!ah_track_computer_calls) return;
    ah_call_status *row = g.directory.arena.make<ah_call_status>();
    if (!row) { g.arena.failed = true; return; }
    row->computer = computer_name ? g.directory.arena.copy(computer_name) : ah_upper(g.directory.arena, o->text("dNSHostName", o->dn));
    row->task = g.directory.arena.copy(task); row->status = status ? g.directory.arena.copy(status) : nullptr;
    row->object_id = o->id ? g.directory.arena.copy(o->id) : nullptr;
    if (g.directory.call_status_tail) g.directory.call_status_tail->next = row; else g.directory.call_status = row;
    g.directory.call_status_tail = row;
}

static void ah_track_resolved_call(ah_graph &g, const char *computer_name, const char *object_id, const char *task, const char *status) {
    if (!ah_track_computer_calls) return;
    ah_object tracked = {}; tracked.id = const_cast<char *>(object_id);
    ah_track_call(g, &tracked, task, status, computer_name);
}

static const char *ah_win32_failure(ah_arena &arena, const char *operation, ULONG status) {
    char number[16]; size_t count = 0;
    do { number[count++] = static_cast<char>('0' + status % 10); status /= 10; } while (status);
    char ordered[16]; for (size_t i = 0; i < count; ++i) ordered[i] = number[count - i - 1]; ordered[count] = 0;
    return ah_concat(arena, operation, ": ", ordered);
}

static bool ah_session_user(const wchar_t *user) {
    if (!user || !*user) return false;
    size_t length = ah_wlen(user);
    if (user[length - 1] == '$') return false;
    const wchar_t anonymous[] = L"anonymous logon";
    size_t i = 0;
    while (user[i] && anonymous[i] && (user[i] == anonymous[i] || user[i] == anonymous[i] - 32)) ++i;
    return user[i] || anonymous[i];
}

static char *ah_user_sid(ah_graph &g, ah_object *computer, const wchar_t *user, const wchar_t *dc, const wchar_t *domain = nullptr) {
    if (!ah_session_user(user)) return nullptr;

    const char *domain_name = domain && *domain ? g.arena.utf8(domain) : g.domain;
    const char *account = g.arena.utf8(user);
    if (!domain_name || !account || ah_eq(domain_name, ".")) return nullptr;
    const char *sam = computer->text("sAMAccountName"); size_t sam_length = ah_len(sam);
    if (sam_length && sam[sam_length - 1] == '$') --sam_length;
    if (ah_eq(domain_name, g.arena.copy(sam, sam_length))) return nullptr;
    const char *directory_id = nullptr;
    if (ah_resolve_directory_account_sid(g, account, domain_name, &directory_id)) return const_cast<char *>(directory_id);
    char *qualified = ah_concat(g.arena, domain_name, "\\", account);
    wchar_t *wide = ah_wide(qualified);
    unsigned char sid[256] = {}; wchar_t resolved_domain[256] = {};
    DWORD sid_size = sizeof(sid), domain_size = 256; SID_NAME_USE use = SidTypeUnknown;
    bool found = wide && ADVAPI32$LookupAccountNameW(dc, wide, sid, &sid_size, resolved_domain, &domain_size, &use);
    ah_free(wide);
    if (found && use == SidTypeUser) return ah_sid_from_psid(g.arena, sid);

    bool current_domain = ah_eq(domain_name, g.domain);
    for (ah_object *crossref = g.directory.objects; crossref && !current_domain; crossref = crossref->next)
        if ((ah_eq(crossref->text("dnsRoot"), g.domain) || ah_eq(crossref->text("nCName"), g.root->dn)) && ah_eq(crossref->text("nETBIOSName"), domain_name)) current_domain = true;
    if (current_domain) {
        ah_object *match = nullptr;
        for (ah_object *o = g.directory.objects; o; o = o->next) {
            if (!ah_eq(o->kind, "User") || !o->raw_sid || !ah_eq(o->text("sAMAccountName"), account)) continue;
            if (match) return nullptr;
            match = o;
        }
        if (match) return match->raw_sid;
    }
    return nullptr;
}

static void ah_add_session(ah_arena &arena, ah_session_info **list, const char *sid, const char *name, uint32_t time, uint32_t idle, SID_NAME_USE usage = SidTypeUser) {
    if (!sid) return;
    for (ah_session_info *existing = *list; existing; existing = existing->next) if (ah_eq(existing->sid, sid) && !existing->computer_sid) return;
    ah_session_info *session = arena.make<ah_session_info>();
    if (!session) return;
    session->sid = arena.copy(sid); session->name = arena.copy(name ? name : sid);
    session->time = time; session->idle = idle; session->usage = usage;
    session->next = *list; *list = session;
}

static void ah_add_computer_session(ah_arena &arena, ah_session_info **list, const char *computer_sid, const char *user_sid, const char *name, uint32_t time = 0, uint32_t idle = 0, bool unique = true) {
    if (!computer_sid || !user_sid) return;
    for (ah_session_info *existing = unique ? *list : nullptr; existing; existing = existing->next)
        if (ah_eq(existing->sid, user_sid) && ah_eq(existing->computer_sid, computer_sid)) return;
    ah_session_info *session = arena.make<ah_session_info>();
    if (!session) return;
    session->computer_sid = arena.copy(computer_sid); session->sid = arena.copy(user_sid);
    session->name = arena.copy(name ? name : user_sid); session->time = time; session->idle = idle; session->usage = SidTypeUser;
    session->next = *list; *list = session;
}

static bool ah_filtered_sid(const char *sid) {
    const char *filtered[] = {"S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-2", "S-1-2-0", "S-1-5-17", "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-0-0", "S-1-0", "S-1-2-1"};
    if (!sid || ah_prefix(sid, "S-1-5-80") || ah_prefix(sid, "S-1-5-82") || ah_prefix(sid, "S-1-5-90") || ah_prefix(sid, "S-1-5-96")) return true;
    for (const char *value : filtered) if (ah_eq(sid, value)) return true;
    return false;
}

static bool ah_machine_principal(const ah_object *computer, const char *sid) {
    size_t length = ah_len(computer->machine_sid);
    return length && ah_prefix(sid, computer->machine_sid) && sid[length] == '-';
}

static const char *ah_wellknown_kind(const char *sid) {
    struct entry { const char *sid, *kind; };
    const entry known[] = {
        {"S-1-0", "User"},
        {"S-1-0-0", "User"},
        {"S-1-1", "User"},
        {"S-1-2", "User"},
        {"S-1-2-0", "Group"},
        {"S-1-2-1", "Group"},
        {"S-1-3", "User"},
        {"S-1-3-0", "User"},
        {"S-1-3-1", "Group"},
        {"S-1-3-2", "Computer"},
        {"S-1-3-3", "Computer"},
        {"S-1-3-4", "Group"},
        {"S-1-4", "User"},
        {"S-1-5", "User"},
        {"S-1-5-1", "Group"},
        {"S-1-5-2", "Group"},
        {"S-1-5-3", "Group"},
        {"S-1-5-4", "Group"},
        {"S-1-5-6", "Group"},
        {"S-1-5-7", "Group"},
        {"S-1-5-8", "Group"},
        {"S-1-5-9", "Group"},
        {"S-1-5-10", "User"},
        {"S-1-5-11", "Group"},
        {"S-1-5-12", "Group"},
        {"S-1-5-13", "Group"},
        {"S-1-5-14", "Group"},
        {"S-1-5-15", "Group"},
        {"S-1-5-17", "User"},
        {"S-1-5-18", "User"},
        {"S-1-5-19", "User"},
        {"S-1-5-20", "User"},
        {"S-1-5-21-0-0-0-496", "Group"},
        {"S-1-5-21-0-0-0-497", "Group"},
        {"S-1-5-32-544", "Group"},
        {"S-1-5-32-545", "Group"},
        {"S-1-5-32-546", "Group"},
        {"S-1-5-32-547", "Group"},
        {"S-1-5-32-548", "Group"},
        {"S-1-5-32-549", "Group"},
        {"S-1-5-32-550", "Group"},
        {"S-1-5-32-551", "Group"},
        {"S-1-5-32-552", "Group"},
        {"S-1-5-32-554", "Group"},
        {"S-1-5-32-555", "Group"},
        {"S-1-5-32-556", "Group"},
        {"S-1-5-32-557", "Group"},
        {"S-1-5-32-558", "Group"},
        {"S-1-5-32-559", "Group"},
        {"S-1-5-32-560", "Group"},
        {"S-1-5-32-561", "Group"},
        {"S-1-5-32-562", "Group"},
        {"S-1-5-32-568", "Group"},
        {"S-1-5-32-569", "Group"},
        {"S-1-5-32-573", "Group"},
        {"S-1-5-32-574", "Group"},
        {"S-1-5-32-575", "Group"},
        {"S-1-5-32-576", "Group"},
        {"S-1-5-32-577", "Group"},
        {"S-1-5-32-578", "Group"},
        {"S-1-5-32-579", "Group"},
        {"S-1-5-32-580", "Group"},
        {"S-1-5-32-581", "Group"},
        {"S-1-5-32-582", "Group"},
        {"S-1-5-32-583", "Group"},
        {"S-1-5-64-10", "Group"},
        {"S-1-5-64-14", "Group"},
        {"S-1-5-64-21", "Group"},
        {"S-1-5-65-1", "Group"},
        {"S-1-5-80", "Group"},
        {"S-1-5-80-0", "Group"},
        {"S-1-5-82", "Group"},
        {"S-1-5-90", "Group"},
        {"S-1-5-96", "Computer"},
        {"S-1-5-113", "User"},
        {"S-1-5-114", "User"},
        {"S-1-5-1000", "Group"},
        {"S-1-18-1", "Group"},
        {"S-1-18-2", "Group"},
        {"S-1-18-3", "Group"},
        {"S-1-18-4", "Group"},
        {"S-1-18-5", "Group"},
        {"S-1-18-6", "Group"},
        {"S-1-1-0", "Group"},
    };
    for (const entry &item : known) if (ah_eq(sid, item.sid)) return item.kind;
    return nullptr;
}

static const char *ah_local_member_id(ah_graph &g, ah_object *computer, const char *sid, SID_NAME_USE usage, const char **kind) {
    if (ah_filtered_sid(sid)) return nullptr;
    const bool dc = (ah_integer(computer, "userAccountControl") & 0x2000) != 0;
    const char *well_known = ah_wellknown_kind(sid);
    if (!dc && well_known && !ah_eq(sid, "S-1-1-0") && !ah_eq(sid, "S-1-5-11")) {
        const char *rid = sid;
        for (const char *p = sid; *p; ++p) if (*p == '-') rid = p;
        *kind = ah_eq(well_known, "User") ? "ADLocalUser" : ah_eq(well_known, "Group") ? "ADLocalGroup" : well_known;
        return ah_concat(g.arena, computer->id, rid);
    }

    if (well_known) {
        *kind = well_known;
        return ah_concat(g.arena, ah_eq(sid, "S-1-5-9") ? g.forest_domain() : g.object_domain(computer), "-", sid);
    }
    ah_object *object = g.sids.find(sid);
    if (object && !(ah_prefix(sid, "S-1-5-32-") && !dc)) { *kind = object->kind ? object->kind : "Base"; return object->id; }
    if (!dc && (ah_prefix(sid, "S-1-5-32-") || ah_machine_principal(computer, sid))) {
        if (usage == SidTypeUser) return nullptr;
        const char *rid = sid;
        for (const char *p = sid; *p; ++p) if (*p == '-') rid = p;
        *kind = (usage == SidTypeAlias || usage == SidTypeGroup || ah_prefix(sid, "S-1-5-32-")) ? "ADLocalGroup" : "Base";
        return ah_concat(g.arena, computer->id, rid);
    }
    const char *resolved_id = nullptr, *resolved_kind = nullptr;
    if (ah_resolve_directory_sid(g, sid, &resolved_id, &resolved_kind)) { *kind = resolved_kind; return resolved_id; }
    if (dc) { *kind = "Base"; return sid; }
    return nullptr;
}

static void ah_session_ref(ah_graph &g, ah_buffer &b, const char *sid, SID_NAME_USE usage, ah_object *computer) {
    const char *kind = "Base";
    if (computer) {
        const char *id = ah_local_member_id(g, computer, sid, usage, &kind);
        if (id) { ah_mark_output_reference(g, id); ah_ref(b, id, kind); } else AH_TEXT(&b, "null");
    } else {
        ah_object *object = g.sids.find(sid);
        if (object) ah_ref(b, object); else ah_ref(b, sid, usage == SidTypeUser ? "User" : "Base");
    }
}

static void ah_session_result(ah_buffer &b, ah_session_info *sessions, bool collected, const char *computer_sid = nullptr, const char *failure_reason = nullptr) {
    AH_TEXT(&b, "{\"Results\":["); bool first = true;
    for (ah_session_info *session = sessions; session; session = session->next) {
        const char *host = session->computer_sid ? session->computer_sid : computer_sid;
        if (!host) continue;
        if (!first) { AH_TEXT(&b, ","); } first = false;
        AH_TEXT(&b, "{\"ComputerSID\":"); ah_string(b, host);
        AH_TEXT(&b, ",\"UserSID\":"); ah_string(b, session->sid); AH_TEXT(&b, "}");
    }
    AH_TEXT(&b, "],\"Collected\":"); if (collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"FailureReason\":");
    if (collected || !failure_reason) AH_TEXT(&b, "null"); else ah_string(b, failure_reason);
    AH_TEXT(&b, "}");
}

static const char *ah_host_account_sid(ah_graph &, const char *, const char *);
static const char *ah_session_lookup_host(ah_graph &g, const char *host) {
    if (ah_object *known = g.hosts.find(host)) return known->id;
    const char *dot = host; while (*dot && *dot != '.') ++dot;
    const char *domain = *dot ? dot + 1 : g.domain;
    if (!*domain) return nullptr;
    const char *account = ah_concat(g.arena, g.arena.copy(host, static_cast<size_t>(dot - host)), "$");
    if (const char *sid = ah_host_account_sid(g, account, g.domain)) return sid;
    return ah_eq(domain, g.domain) ? nullptr : ah_host_account_sid(g, account, domain);
}

#include "host_resolution.hpp"

static const char *ah_session_host_sid_uncached(ah_graph &g, ah_object *computer, const wchar_t *client) {
    if (!client || !*client) return nullptr;
    while (*client == '\\') ++client;
    if (!*client) return nullptr;
    char *host = g.arena.utf8(client); if (!host) return nullptr;
    if (ah_eq(host, "127.0.0.1") || ah_eq(host, "::1") || ah_eq(host, "[::1]") || ah_eq(host, "localhost")) return computer->id;
    if (ah_object *known = g.hosts.find(host)) return known->id;
    size_t length = ah_len(host);
    if (length > 2 && host[0] == '[' && host[length - 1] == ']') host = g.arena.copy(host + 1, length - 2);
    if (const char *sid = ah_host_workstation_sid(g, host)) return sid;
    if (const char *sid = ah_host_netbios_sid(g, host)) return sid;
    ah_native_library winsock(L"ws2_32.dll");
    auto parse = winsock.find<decltype(&inet_pton)>("inet_pton");
    IN_ADDR ipv4 = {}; IN6_ADDR ipv6 = {};
    const bool ip = parse && (parse(AF_INET, host, &ipv4) == 1 || parse(AF_INET6, host, &ipv6) == 1);
    if (!ip) if (const char *sid = ah_session_lookup_host(g, host)) return sid;

    auto address = winsock.find<decltype(&getaddrinfo)>("getaddrinfo");
    auto name = winsock.find<decltype(&getnameinfo)>("getnameinfo");
    auto release = winsock.find<decltype(&freeaddrinfo)>("freeaddrinfo");
    WSADATA data = {};
    if (!address || !name || !release || WS2_32$WSAStartup(MAKEWORD(2, 2), &data)) return nullptr;
    ADDRINFOA hints = {}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    ADDRINFOA *addresses = nullptr; const char *result = nullptr;
    if (!address(host, nullptr, &hints, &addresses)) {
        for (ADDRINFOA *item = addresses; item; item = item->ai_next) {
            char resolved[1025] = {};
            if (name(item->ai_addr, static_cast<INT>(item->ai_addrlen), resolved, sizeof(resolved), nullptr, 0, NI_NAMEREQD)) continue;
            result = ah_session_lookup_host(g, resolved);
            if (result) break;
        }
        release(addresses);
    }
    WS2_32$WSACleanup();
    return result;
}
static const char *ah_session_host_sid(ah_graph &g,ah_object *computer,const wchar_t *client){
    if(!client)return nullptr;
    while(*client=='\\')++client;
    const char *host=g.arena.utf8(client);if(!host)return nullptr;
    const bool loopback=ah_eq(host,"127.0.0.1")||ah_eq(host,"::1")||ah_eq(host,"[::1]")||ah_eq(host,"localhost");
    const char *sid=nullptr;if(!loopback&&ah_cached_host_sid(host,&sid))return sid;
    sid=ah_session_host_sid_uncached(g,computer,client);if(!loopback)ah_cache_host_sid(host,sid);return sid;
}

static void ah_collect_smb_sessions(ah_graph &g, ah_object *o, const wchar_t *dc) {
    wchar_t *host = ah_wide(ah_api_hostname(g, o));
    if (!host) { o->sessions_failure_reason = "HostNameUnavailable"; return; }
    wchar_t current_user[256] = {}; DWORD current_length = 256;
    ah_native_library advapi(L"advapi32.dll");
    auto get_user = advapi.find<decltype(&GetUserNameW)>("GetUserNameW");

    const char *collector_user = get_user && get_user(current_user, &current_length) ? g.arena.utf8(current_user) : nullptr;
    DWORD resume = 0;
    for (;;) {
        SESSION_INFO_10 *entries = nullptr; DWORD read = 0, total = 0;
        NET_API_STATUS status;
        {
            ah_session_credentials alternate;
            if (!alternate.valid()) {

                o->consumer_failed = true;
                BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: session impersonation initialization failed for %s; computer omitted", o->id);
                ah_free(host); return;
            }
            status = NETAPI32$NetSessionEnum(host, nullptr, nullptr, 10, reinterpret_cast<LPBYTE *>(&entries), MAX_PREFERRED_LENGTH, &read, &total, &resume);
        }
        if (ah_local_admin_session && status != NERR_Success && status != ERROR_MORE_DATA) {
            if (entries) { NETAPI32$NetApiBufferFree(entries); entries = nullptr; }
            read = total = resume = 0;
            status = NETAPI32$NetSessionEnum(host, nullptr, nullptr, 10, reinterpret_cast<LPBYTE *>(&entries), MAX_PREFERRED_LENGTH, &read, &total, &resume);
        }
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            o->sessions_collected = false; o->sessions_failure_reason = ah_netapi_status_name(g.arena, status);
            if (entries) NETAPI32$NetApiBufferFree(entries);
            break;
        }
        o->sessions_collected = true;
        for (DWORD i = 0; i < read; ++i) {
            if (!ah_session_user(entries[i].sesi10_username)) continue;
            const char *client_sid = ah_session_host_sid(g, o, entries[i].sesi10_cname);
            if (!client_sid) continue;
            const char *username = g.arena.utf8(entries[i].sesi10_username);
            if (collector_user && ah_eq(collector_user, username)) continue;
            ah_session_info *matches = nullptr;
            if (ah_gc_user_matches(g, username, &matches)) {
                for (ah_session_info *user = matches; user; user = user->next)
                    ah_add_computer_session(g.arena, &o->sessions, client_sid, user->sid, username, entries[i].sesi10_time, entries[i].sesi10_idle_time, false);
            } else {
                ah_add_computer_session(g.arena, &o->sessions, client_sid, ah_user_sid(g, o, entries[i].sesi10_username, dc), username, entries[i].sesi10_time, entries[i].sesi10_idle_time, false);
            }
        }
        if (entries) NETAPI32$NetApiBufferFree(entries);
        if (status != ERROR_MORE_DATA || g.arena.failed) break;
    }
    ah_track_call(g, o, "NetSessionEnum", o->sessions_collected ? "Success" : o->sessions_failure_reason);
    ah_track_call(g, o, "NetSessionEnum", o->sessions_collected ? "Success" : o->sessions_failure_reason);
    ah_free(host);
}

static void ah_collect_privileged_sessions(ah_graph &g, ah_object *o, const wchar_t *dc) {
    wchar_t *host = ah_wide(o->text("dNSHostName"));
    if (!host) { o->privileged_failure_reason = "HostNameUnavailable"; return; }
    DWORD resume = 0;
    for (;;) {
        WKSTA_USER_INFO_1 *entries = nullptr; DWORD read = 0, total = 0;
        NET_API_STATUS status;
        {
            ah_session_credentials alternate;
            if (!alternate.valid()) {
                o->consumer_failed = true;
                BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: privileged-session impersonation initialization failed for %s; computer omitted", o->id);
                ah_free(host); return;
            }
            status = NETAPI32$NetWkstaUserEnum(host, 1, reinterpret_cast<LPBYTE *>(&entries), MAX_PREFERRED_LENGTH, &read, &total, &resume);
        }
        if (ah_local_admin_session && status != NERR_Success && status != ERROR_MORE_DATA) {
            if (entries) { NETAPI32$NetApiBufferFree(entries); entries = nullptr; }
            read = total = resume = 0;
            status = NETAPI32$NetWkstaUserEnum(host, 1, reinterpret_cast<LPBYTE *>(&entries), MAX_PREFERRED_LENGTH, &read, &total, &resume);
        }
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            o->privileged_collected = false; o->privileged_failure_reason = ah_netapi_status_name(g.arena, status);
            if (entries) NETAPI32$NetApiBufferFree(entries);
            break;
        }
        o->privileged_collected = true;
        for (DWORD i = 0; i < read; ++i) {
            const wchar_t *account = entries[i].wkui1_username, *domain = entries[i].wkui1_logon_domain;
            if (!domain || !*domain) continue;
            bool domain_space = false; for (const wchar_t *p = domain; *p; ++p) if (*p == L' ') domain_space = true;
            if (domain_space) continue;
            char *sid = ah_user_sid(g, o, account, dc, domain);
            char *name = sid ? ah_concat(g.arena, g.arena.utf8(account), "@", g.arena.utf8(domain)) : nullptr;

            ah_add_computer_session(g.arena, &o->privileged_sessions, o->id, sid, name, 0, 0, false);
        }
        if (entries) NETAPI32$NetApiBufferFree(entries);
        if (status != ERROR_MORE_DATA || g.arena.failed) break;
    }
    ah_track_call(g, o, "NetWkstaUserEnum", o->privileged_collected ? "Success" : o->privileged_failure_reason);
    ah_track_call(g, o, "NetWkstaUserEnum", o->privileged_collected ? "Success" : o->privileged_failure_reason);
    ah_free(host);
}

static bool ah_registry_session_sid(const char *sid) {
    if (!sid || !ah_prefix(sid, "S-1-5-21-")) return false;
    const char *p = sid + 9;
    for (unsigned int component = 0; component < 4; ++component) {
        if (*p < '0' || *p > '9') return false;
        while (*p >= '0' && *p <= '9') ++p;
        if (component < 3 && *p++ != '-') return false;
    }
    return *p == 0;
}

static bool ah_registry_domain_user(ah_graph &g, ah_object *computer, const char *sid) {
    if (!ah_registry_session_sid(sid)) return false;
    if (!(ah_integer(computer, "userAccountControl") & 0x2000) && ah_machine_principal(computer, sid)) return false;
    const char *id = nullptr, *kind = nullptr;
    return ah_resolve_directory_sid(g, sid, &id, &kind);
}

static void ah_track_registry_sessions(ah_graph &g, ah_object *o, const char *api_name) {
    if (!ah_track_computer_calls) return;
    const char *status = o->registry_collected ? "Success" : o->registry_failure_reason;
    ah_track_call(g, o, "RegistrySessionEnum", status, ah_upper(g.arena, api_name));
    ah_track_call(g, o, "RegistrySessions", status, ah_upper(g.arena, o->text("dNSHostName", o->dn)));
}

static void ah_collect_registry_sessions(ah_graph &g, ah_object *o) {
    const char *api_name = ah_api_hostname(g, o);
    wchar_t *host = ah_wide(api_name);
    if (!host) { o->registry_collected = false; o->registry_failure_reason = "HostNameUnavailable"; ah_track_registry_sessions(g, o, api_name); return; }
    HKEY root = nullptr;
    LONG status = ADVAPI32$RegConnectRegistryW(host, HKEY_USERS, &root); ah_free(host);
    if (status != ERROR_SUCCESS) { o->registry_collected = false; o->registry_failure_reason = ah_win32_failure(g.arena, "RegConnectRegistry(HKU)", status); ah_track_registry_sessions(g, o, api_name); return; }
    o->registry_collected = true;
    for (DWORD index = 0;; ++index) {
        wchar_t name[256] = {}; DWORD length = sizeof(name) / sizeof(name[0]);
        status = ADVAPI32$RegEnumKeyExW(root, index, name, &length, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) { o->registry_collected = false; o->registry_failure_reason = ah_win32_failure(g.arena, "RegEnumKey(HKU)", status); break; }
        char *sid = g.arena.utf8(name);
        if (!ah_registry_session_sid(sid)) continue;
        if (!ah_registry_domain_user(g, o, sid)) continue;
        ah_object *user = g.sids.find(sid);
        ah_add_computer_session(g.arena, &o->registry_sessions, o->id, user ? user->id : sid, sid);
    }
    ah_track_registry_sessions(g, o, api_name);
    ADVAPI32$RegCloseKey(root);
}

#include "sam_groups.hpp"

static LONG ah_registry_dword_status(ah_object *o, const wchar_t *path, const wchar_t *name, uint32_t *out, HKEY connected_root) {
    HKEY root = connected_root, key = nullptr;
    LONG status = ERROR_SUCCESS;
    if (!root) {
        wchar_t *host = ah_wide(o->text("dNSHostName"));
        if (!host) return ERROR_INVALID_NAME;
        status = ADVAPI32$RegConnectRegistryW(host, HKEY_LOCAL_MACHINE, &root);
        ah_free(host);
    }
    if (status == ERROR_SUCCESS) status = ADVAPI32$RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &key);
    if (status == ERROR_SUCCESS) {
        DWORD type = 0, size = sizeof(*out);
        status = ADVAPI32$RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(out), &size);
        if (status == ERROR_SUCCESS && (type != REG_DWORD || size != sizeof(*out))) status = ERROR_INVALID_DATA;
    }
    if (key) ADVAPI32$RegCloseKey(key);
    if (root) ADVAPI32$RegCloseKey(root);
    return status;
}

static LONG ah_registry_text_status(ah_arena &arena, ah_object *o, const wchar_t *path, const wchar_t *name, char **out) {
    HKEY root = nullptr, key = nullptr;
    wchar_t *host = ah_wide(o->text("dNSHostName"));
    if (!host) return ERROR_INVALID_NAME;
    LONG status = ADVAPI32$RegConnectRegistryW(host, HKEY_LOCAL_MACHINE, &root); ah_free(host);
    if (status == ERROR_SUCCESS) status = ADVAPI32$RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (status == ERROR_SUCCESS) {
        DWORD type = 0, size = 0;
        status = ADVAPI32$RegQueryValueExW(key, name, nullptr, &type, nullptr, &size);
        if (status == ERROR_SUCCESS && ((type != REG_SZ && type != REG_EXPAND_SZ) || size % sizeof(wchar_t) || size > 16 * 1024 * 1024)) status = ERROR_INVALID_DATA;
        if (status == ERROR_SUCCESS) {
            wchar_t *data = ah_alloc<wchar_t>(static_cast<size_t>(size) + sizeof(wchar_t));
            if (!data) status = ERROR_NOT_ENOUGH_MEMORY;
            else {
                data[size / sizeof(wchar_t)] = 0;
                status = ADVAPI32$RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(data), &size);
                if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) && size % sizeof(wchar_t) == 0) { *out = arena.utf8(data); if (!*out) status = ERROR_NOT_ENOUGH_MEMORY; }
                else if (status == ERROR_SUCCESS) status = ERROR_INVALID_DATA;
                ah_free(data);
            }
        }
    }
    if (key) ADVAPI32$RegCloseKey(key);
    if (root) ADVAPI32$RegCloseKey(root);
    return status;
}

static LONG ah_registry_binary_status(ah_arena &arena, ah_object *o, const wchar_t *path, const wchar_t *name, ah_value **out, HKEY connected_root) {
    HKEY root = connected_root, key = nullptr;
    LONG status = ERROR_SUCCESS;
    if (!root) {
        wchar_t *host = ah_wide(o->text("dNSHostName"));
        if (!host) return ERROR_INVALID_NAME;
        status = ADVAPI32$RegConnectRegistryW(host, HKEY_LOCAL_MACHINE, &root);
        ah_free(host);
    }
    if (status == ERROR_SUCCESS) status = ADVAPI32$RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE, &key);
    if (status == ERROR_SUCCESS) {
        DWORD type = 0, size = 0;
        status = ADVAPI32$RegQueryValueExW(key, name, nullptr, &type, nullptr, &size);
        if (status == ERROR_SUCCESS && (type != REG_BINARY || !size)) status = ERROR_INVALID_DATA;
        if (status == ERROR_SUCCESS) {
            char *data = static_cast<char *>(arena.alloc(size));
            if (!data) status = ERROR_NOT_ENOUGH_MEMORY;
            else {
                status = ADVAPI32$RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(data), &size);
                if (status == ERROR_SUCCESS && type != REG_BINARY) status = ERROR_INVALID_DATA;
                if (status == ERROR_SUCCESS) {
                    *out = arena.make<ah_value>();
                    if (*out) { (*out)->data = data; (*out)->size = size; }
                    else status = ERROR_NOT_ENOUGH_MEMORY;
                }
            }
        }
    }
    if (key) ADVAPI32$RegCloseKey(key);
    if (root) ADVAPI32$RegCloseKey(root);
    return status;
}

static void ah_collect_ntlm_registry_strategy(ah_graph &g, ah_object *o);
static void ah_collect_azure_registry_strategy(ah_graph &g, ah_object *o);

static void ah_collect_host_registry(ah_graph &g, ah_object *o, int collection) {
    if (collection & AH_NTLM_REGISTRY) { ah_computer_delay(); ah_collect_ntlm_registry_strategy(g, o); }
    if (collection & AH_AZURE_REGISTRY) { ah_computer_delay(); ah_collect_azure_registry_strategy(g, o); }
    if (collection & AH_WEBCLIENT) {
        wchar_t *pipe = ah_wide(ah_concat(g.arena, "\\\\", ah_api_hostname(g, o), "\\pipe\\DAV RPC SERVICE"));
        HANDLE handle = pipe ? KERNEL32$CreateFileW(pipe, MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr) : INVALID_HANDLE_VALUE;
        DWORD status = handle == INVALID_HANDLE_VALUE ? KERNEL32$GetLastError() : ERROR_SUCCESS;
        if (handle != INVALID_HANDLE_VALUE) KERNEL32$CloseHandle(handle);
        ah_free(pipe);
        if (status == ERROR_SUCCESS || status == ERROR_ACCESS_DENIED) { o->webclient_collected = true; o->webclient_running = true; }
        else if (status == ERROR_FILE_NOT_FOUND || status == ERROR_BAD_NETPATH || status == ERROR_NETNAME_DELETED || status == ERROR_NETWORK_ACCESS_DENIED) { o->webclient_collected = true; o->webclient_running = false; }
        else o->webclient_failure = ah_win32_failure(g.arena, "WebClient DAV named pipe", status);
    }
    ah_object registry_target = *o;
    ah_value target_value = {const_cast<char *>(ah_api_hostname(g, o)), 0, nullptr}; target_value.size = ah_len(target_value.data);
    ah_attr target_attribute = {const_cast<char *>("dNSHostName"), &target_value, &target_value, registry_target.attributes};
    registry_target.attributes = &target_attribute;
    if (o->dc_registry_requested) {
        ah_computer_delay();
        LONG status = ah_registry_dword_status(&registry_target, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel", L"CertificateMappingMethods", &o->cert_mapping);
        o->cert_mapping_valid = status == ERROR_SUCCESS;
        o->cert_mapping_collected = status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
        if (!o->cert_mapping_collected) o->cert_mapping_failure = ah_registry_status_reason(g.arena, "CertificateMappingMethods", status);
        status = ah_registry_dword_status(&registry_target, L"SYSTEM\\CurrentControlSet\\Services\\Kdc", L"StrongCertificateBindingEnforcement", &o->strong_binding);
        o->strong_binding_valid = status == ERROR_SUCCESS;
        o->strong_binding_collected = status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
        if (!o->strong_binding_collected) o->strong_binding_failure = ah_registry_status_reason(g.arena, "StrongCertificateBindingEnforcement", status);
        status = ah_registry_text_status(g.arena, &registry_target, L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", L"VulnerableChannelAllowList", &o->vulnerable_netlogon);
        o->vulnerable_netlogon_valid = status == ERROR_SUCCESS;
        o->vulnerable_netlogon_collected = status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND;
        if (!o->vulnerable_netlogon_collected) o->vulnerable_netlogon_failure = ah_registry_status_reason(g.arena, "VulnerableChannelAllowList", status);
    }
    ah_registry_wmi_query queries[] = {
        {L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel", L"CertificateMappingMethods", REG_DWORD, &o->cert_mapping, nullptr, nullptr, &o->cert_mapping_valid, &o->cert_mapping_collected, &o->cert_mapping_failure},
        {L"SYSTEM\\CurrentControlSet\\Services\\Kdc", L"StrongCertificateBindingEnforcement", REG_DWORD, &o->strong_binding, nullptr, nullptr, &o->strong_binding_valid, &o->strong_binding_collected, &o->strong_binding_failure},
        {L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters", L"VulnerableChannelAllowList", REG_SZ, nullptr, nullptr, &o->vulnerable_netlogon, &o->vulnerable_netlogon_valid, &o->vulnerable_netlogon_collected, &o->vulnerable_netlogon_failure}
    };
    if (o->dc_registry_requested) ah_registry_wmi_fallback(g, o, queries, sizeof(queries) / sizeof(queries[0]));

}

#include "wmi_sessions.hpp"
#include "../registry/registry_strategy.hpp"

static void ah_collect_service_probes(ah_graph &g, ah_object *o);
static bool ah_tcp_open(const char *host, uint16_t port);
static bool ah_tcp_open_timeout(const char *host, uint16_t port, int milliseconds);

static bool ah_computer_active(const ah_object *o, uint64_t now) {
    const uint64_t sixty_days = 60ULL * 24 * 60 * 60 * 10000000;
    uint64_t threshold = now > sixty_days ? now - sixty_days : 0;
    return ah_unsigned(o->text("pwdLastSet")) >= threshold || ah_unsigned(o->text("lastLogonTimestamp")) >= threshold;
}

static const char *ah_host_availability(ah_object *o) {
    if (o->values("operatingSystem") && !ah_prefix(o->text("operatingSystem"), "Windows")) return "NonWindowsOS";
    if (!ah_skip_password_age_check) {
        ah_native_library kernel(L"kernel32.dll");
        auto current_time = kernel.find<decltype(&GetSystemTimeAsFileTime)>("GetSystemTimeAsFileTime");
        if (!current_time) return "ClockUnavailable";
        FILETIME time = {}; current_time(&time);
        uint64_t now = (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
        if (!ah_computer_active(o, now)) return "NotActive";
    }
    if (!ah_skip_port_scan && !ah_tcp_open_timeout(o->text("dNSHostName"), 445, ah_port_scan_timeout)) return "PortNotOpen";
    return nullptr;
}

static void ah_collect_host_sessions(ah_graph &g, ah_object *o, const wchar_t *dc, int collection) {
    if (o->consumer_failed || !ah_eq(o->kind, "Computer")) return;
    int work = AH_SESSION | AH_LOGGEDON | AH_LOCAL_GROUPS | AH_USER_RIGHTS | AH_CA_REGISTRY | AH_DC_REGISTRY | AH_NTLM_REGISTRY | AH_AZURE_REGISTRY | AH_WEBCLIENT | AH_LDAP_SERVICES | AH_SMBINFO;
    if (!(collection & work)) return;
    o->hostavailability_checked = true;
    o->host_failure = ah_host_availability(o);
    o->host_connectable = o->host_failure == nullptr;
    if (ah_eq(o->host_failure,"PortNotOpen")) {

        ah_object tracked=*o;tracked.id=nullptr;
        ah_track_call(g,&tracked,"CheckAvailability","PortNotOpen");
    }
    ah_track_call(g, o, "ComputerAvailability", o->host_connectable ? "Success" : o->host_failure);
    if (!o->host_connectable) return;
    o->webclient_requested = (collection & AH_WEBCLIENT) != 0;
    o->ntlm_registry_requested = (collection & AH_NTLM_REGISTRY) != 0;
    o->dc_registry_requested = (collection & AH_DC_REGISTRY) && (ah_integer(o, "userAccountControl") & 0x2000);

    if (collection & AH_SESSION) {
        if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: host %s sessions", o->text("dNSHostName")); }
        ah_computer_delay(); ah_collect_smb_sessions(g, o, dc);
        if (o->consumer_failed) return;
    }
    if (collection & AH_LOGGEDON) {
        ah_computer_delay(); ah_collect_privileged_sessions(g, o, dc);
        if (o->consumer_failed) return;
        if (!ah_skip_registry_loggedon) { ah_computer_delay(); ah_collect_registry_sessions(g, o); }
        if (ah_extended_sessions) { ah_collect_rdp_sessions(g, o, dc); ah_collect_wmi_sessions(g, o, dc); }
    }
    if (collection & AH_USER_RIGHTS) { ah_computer_delay(); ah_collect_user_rights(g, o); }
    if (collection & (AH_DC_REGISTRY | AH_NTLM_REGISTRY | AH_AZURE_REGISTRY | AH_WEBCLIENT)) {
        if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: host %s registry", o->text("dNSHostName")); }
        ah_collect_host_registry(g, o, collection);
    }
    if (collection & (AH_LDAP_SERVICES | AH_SMBINFO)) ah_collect_service_probes(g, o);
    if (collection & AH_LOCAL_GROUPS) { ah_computer_delay(); ah_collect_local_groups(g, o); }
    if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: host %s done", o->text("dNSHostName")); }
}

static void ah_local_names_result(ah_graph &g, ah_buffer &b, ah_object *o, ah_session_info *members) {
    AH_TEXT(&b, "["); bool first = true;
    if (ah_integer(o, "userAccountControl") & 0x2000) { AH_TEXT(&b, "]"); return; }
    for (ah_session_info *member = members; member; member = member->next) {
        if (!ah_machine_principal(o, member->sid) || !member->name || ah_eq(member->name, member->sid)) continue;
        const char *kind = nullptr, *id = ah_local_member_id(g, o, member->sid, member->usage, &kind);
        if (!id) continue;
        if (!first) { AH_TEXT(&b, ","); } first = false;
        AH_TEXT(&b, "{\"ObjectId\":"); ah_string(b, id);
        AH_TEXT(&b, ",\"PrincipalName\":"); ah_string(b, member->name); AH_TEXT(&b, "}");
    }
    AH_TEXT(&b, "]");
}

static void ah_local_groups_result(ah_graph &g, ah_buffer &b, ah_object *computer) {
    AH_TEXT(&b, "["); bool first = true;
    for (ah_local_group_info *group = computer->local_groups; group; group = group->next) {
        if (!group->sid) continue;

        if ((ah_integer(computer, "userAccountControl") & 0x2000) && ah_builtin(group->raw_sid))
            ah_mark_output_reference(g, group->sid);
        if (!first) { AH_TEXT(&b, ","); } first = false;
        AH_TEXT(&b, "{"); ah_fields fields(b);
        fields.text("ObjectIdentifier", group->sid); fields.text("Name", group->name);
        fields.key("Results"); AH_TEXT(&b, "["); bool member_first = true;
        for (ah_session_info *member = group->members; member; member = member->next) {
            const char *kind = nullptr;
            if (!ah_local_member_id(g, computer, member->sid, member->usage, &kind)) continue;
            if (!member_first) { AH_TEXT(&b, ","); } member_first = false;
            ah_session_ref(g, b, member->sid, member->usage, computer);
        }
        AH_TEXT(&b, "],\"LocalNames\":"); ah_local_names_result(g, b, computer, group->members);
        AH_TEXT(&b, ",\"Collected\":"); if (group->collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
        AH_TEXT(&b, ",\"FailureReason\":");
        if (group->collected) AH_TEXT(&b, "null"); else ah_string(b, group->failure_reason ? group->failure_reason : "LocalGroupQueryFailed");
        AH_TEXT(&b, "}");
    }
    AH_TEXT(&b, "]");
}

static ah_object *ah_ca_host_context(ah_graph &g, ah_object *ca) {
    if (ca->registry_host_resolved) return ca->registry_host;
    ca->registry_host_resolved = true;
    const char *name = ca->text("dNSHostName");
    if (!*name) return nullptr;
    ah_object *host = g.hosts.find(name);
    bool temporary = host == nullptr;
    if (host && g.parallel_worker) {
        ah_object *copy=g.arena.make<ah_object>();
        if(!copy)return nullptr;
        *copy=*host;host=copy;
    }
    if (!host) {
        const char *sid = ah_session_lookup_host(g, name);
        if (!sid) return nullptr;
        host = g.arena.make<ah_object>(); if (!host) return nullptr;
        host->kind = "Computer"; host->type = L"computers";
        host->id = host->raw_sid = g.arena.copy(sid);
        g.directory.value(g.directory.attribute(host, "dNSHostName"), name, ah_len(name));
    }
    wchar_t *wide = ah_wide(name);
    if (wide) { ah_collect_machine_sid_sam(g, host, wide, name); ah_free(wide); }

    if (temporary && host->machine_sid && host->id) {
        const char *rid = host->id;
        for (const char *p = host->id; *p; ++p) if (*p == '-') rid = p;
        const char *domain_sid = g.arena.copy(host->id, static_cast<size_t>(rid - host->id));
        if (ah_eq(domain_sid, host->machine_sid)) g.directory.value(g.directory.attribute(host, "userAccountControl"), "8192", 4);
    }
    ca->registry_host = host; return host;
}

static bool ah_ca_registry_principal(ah_graph &g, ah_buffer &b, ah_object *ca, const char *sid, const char *right = nullptr, bool inherited = false) {
    if (!sid) return false;
    const char *id = nullptr, *kind = nullptr;
    if (!ah_filtered_sid(sid)) {
        ah_object *host = ah_ca_host_context(g, ca);
        bool dc = host && (ah_integer(host, "userAccountControl") & 0x2000);
        const char *well_known = ah_wellknown_kind(sid);
        if (dc && ah_resolve_directory_sid(g, sid, &id, &kind)) {

        } else if (well_known) {
            if (host && !dc && !ah_eq(sid, "S-1-1-0") && !ah_eq(sid, "S-1-5-11")) {
                const char *rid = sid;
                for (const char *p = sid; *p; ++p) if (*p == '-') rid = p;
                id = ah_concat(g.arena, host->id, rid);
                kind = ah_eq(well_known, "User") ? "ADLocalUser" : ah_eq(well_known, "Group") ? "ADLocalGroup" : well_known;
            } else {
                const char *domain = ah_eq(sid, "S-1-5-9") ? g.forest_domain() : g.object_domain(ca);
                id = ah_concat(g.arena, domain, "-", sid); kind = well_known;
            }
        } else if (host && ah_machine_principal(host, sid)) {

            const char *rid = sid;
            for (const char *p = sid; *p; ++p) if (*p == '-') rid = p;
            id = ah_concat(g.arena, host->id, rid); kind = "ADLocalGroup";
        }
        if (!id) {
            ah_resolve_directory_sid(g, sid, &id, &kind);
        }
    }
    if (!id || !kind) {
        if (!right) return false;
        id = sid; kind = "Base";
    }

    if (ah_builtin(sid) && !ah_eq(id, sid) && ah_wellknown_identifier_kind(id)) ah_record_output_reference(g, id, true);
    if (g.arena.failed) { b.failed = true; return false; }
    if (!right) { ah_ref(b, id, kind); return !b.failed; }
    AH_TEXT(&b, "{"); ah_fields fields(b);
    fields.text("PrincipalSID", id); fields.text("PrincipalType", kind); fields.text("RightName", right);
    fields.boolean("IsInherited", inherited);
    fields.nullable_text("InheritanceHash", nullptr);
    fields.boolean("IsPermissionForOwnerRightsSid", false); fields.boolean("IsInheritedPermissionForOwnerRightsSid", false);
    AH_TEXT(&b, "}"); return !b.failed;
}
