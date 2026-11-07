#pragma once

struct ah_sam_rid { ULONG rid; LSA_UNICODE_STRING name; };
struct ah_sam_domain { char *name, *sid; PSID binary; ah_sam_domain *next; };

class ah_sam_api final {
    ah_native_library library;
public:
    using connect_type = NTSTATUS (NTAPI *)(LSA_UNICODE_STRING *, HANDLE *, ACCESS_MASK, LSA_OBJECT_ATTRIBUTES *);
    using enumerate_type = NTSTATUS (NTAPI *)(HANDLE, ULONG *, void **, ULONG, ULONG *);
    using domain_lookup_type = NTSTATUS (NTAPI *)(HANDLE, LSA_UNICODE_STRING *, PSID *);
    using domain_open_type = NTSTATUS (NTAPI *)(HANDLE, ACCESS_MASK, PSID, HANDLE *);
    using alias_open_type = NTSTATUS (NTAPI *)(HANDLE, ACCESS_MASK, ULONG, HANDLE *);
    using members_type = NTSTATUS (NTAPI *)(HANDLE, PSID **, ULONG *);
    using lookup_type = NTSTATUS (NTAPI *)(HANDLE, ULONG, ULONG *, LSA_UNICODE_STRING **, SID_NAME_USE **);
    using free_type = NTSTATUS (NTAPI *)(void *);
    using close_type = NTSTATUS (NTAPI *)(HANDLE);
    connect_type connect; enumerate_type domains, aliases; domain_lookup_type lookup_domain;
    domain_open_type open_domain; alias_open_type open_alias; members_type members; lookup_type lookup;
    free_type release; close_type close;
    ah_sam_api() : library(L"samlib.dll"),
        connect(library.find<connect_type>("SamConnect")), domains(library.find<enumerate_type>("SamEnumerateDomainsInSamServer")),
        aliases(library.find<enumerate_type>("SamEnumerateAliasesInDomain")), lookup_domain(library.find<domain_lookup_type>("SamLookupDomainInSamServer")),
        open_domain(library.find<domain_open_type>("SamOpenDomain")), open_alias(library.find<alias_open_type>("SamOpenAlias")),
        members(library.find<members_type>("SamGetMembersInAlias")), lookup(library.find<lookup_type>("SamLookupIdsInDomain")),
        release(library.find<free_type>("SamFreeMemory")), close(library.find<close_type>("SamCloseHandle")) {}
    bool valid() const { return connect && domains && aliases && lookup_domain && open_domain && open_alias && members && lookup && release && close; }
};
class ah_sam_handle final {
    ah_sam_api &api;
public:
    HANDLE value = nullptr;
    explicit ah_sam_handle(ah_sam_api &methods) : api(methods) {}
    ~ah_sam_handle() { if (value) api.close(value); }
    ah_sam_handle(const ah_sam_handle &) = delete;
    ah_sam_handle &operator=(const ah_sam_handle &) = delete;
};
static char *ah_sam_name(ah_arena &arena, const LSA_UNICODE_STRING &name) {
    if (name.Length % sizeof(wchar_t) || (name.Length && !name.Buffer)) return nullptr;
    size_t count = name.Length / sizeof(wchar_t);
    wchar_t *copy = ah_alloc<wchar_t>((count + 1) * sizeof(wchar_t));
    if (!copy) { arena.failed = true; return nullptr; }
    for (size_t i = 0; i < count; ++i) copy[i] = name.Buffer[i];
    copy[count] = 0; char *result = arena.utf8(copy); ah_free(copy); return result;
}
static const char *ah_sid_rid(ah_arena &arena, const char *sid, ULONG rid) {
    char digits[32]; return ah_concat(arena, sid, "-", ah_decimal(digits + sizeof(digits), rid));
}
static void ah_collect_machine_sid_sam(ah_graph &g, ah_object *o, const wchar_t *host, const char *computer_name = nullptr) {
    if (o->machine_sid) return;
    if(const char *cached=ah_cached_machine_sid(o->id)){o->machine_sid=const_cast<char *>(cached);return;}
    ah_sam_api api; ah_sam_handle server(api);
    LSA_UNICODE_STRING name = {static_cast<USHORT>(ah_wlen(host) * sizeof(wchar_t)), static_cast<USHORT>(ah_wlen(host) * sizeof(wchar_t)), const_cast<wchar_t *>(host)};
    LSA_OBJECT_ATTRIBUTES attributes = {}; attributes.Length = sizeof(attributes);
    NTSTATUS opened = api.valid() ? api.connect(&name, &server.value, 0x31, &attributes) : static_cast<NTSTATUS>(0xc000007aU);
    if (opened || !server.value) {
        if (computer_name) ah_track_call(g, o, "OpenSamServer", ah_ntstatus_name(g.arena, static_cast<ULONG>(opened)), computer_name);
        return;
    }
    ULONG context = 0;
    NTSTATUS status;
    do {
        ah_sam_rid *domains = nullptr; ULONG count = 0, previous = context;
        status = api.domains(server.value, &context, reinterpret_cast<void **>(&domains), 0xffffffffUL, &count);
        if ((status && static_cast<ULONG>(status) != 0x105U) || count > 100000 || (count && !domains)) { if (domains) api.release(domains); return; }
        for (ULONG i = 0; i < count && !o->machine_sid; ++i) {
            char *domain_name = ah_sam_name(g.arena, domains[i].name);
            if (!domain_name || ah_eq(domain_name, "builtin")) continue;
            PSID sid = nullptr;
            if (!api.lookup_domain(server.value, &domains[i].name, &sid) && sid) o->machine_sid = ah_sid_from_psid(g.arena, sid);
            if (sid) api.release(sid);
        }
        if (domains) api.release(domains);
        if (status && (!count || previous == context)) return;
    } while (!o->machine_sid && static_cast<ULONG>(status) == 0x105U && !g.arena.failed);
    if(o->machine_sid) {
        ah_cache_machine_sid(o->id,o->machine_sid);
        if (computer_name) ah_track_call(g, o, "GetMachineSid", "Success", computer_name);
    }
}

static void ah_collect_local_groups(ah_graph &g, ah_object *o) {
    if(!o->machine_sid)if(const char *cached=ah_cached_machine_sid(o->id))o->machine_sid=const_cast<char *>(cached);
    wchar_t *host = ah_wide(o->text("dNSHostName"));
    if (!host || !o->raw_sid) { ah_free(host); return; }
    ah_sam_api api; ah_sam_handle server(api);
    LSA_UNICODE_STRING name = {static_cast<USHORT>(ah_wlen(host) * sizeof(wchar_t)), static_cast<USHORT>(ah_wlen(host) * sizeof(wchar_t)), host};
    LSA_OBJECT_ATTRIBUTES attributes = {}; attributes.Length = sizeof(attributes);
    NTSTATUS status = api.valid() ? api.connect(&name, &server.value, 0x31, &attributes) : static_cast<NTSTATUS>(0xc000007aU);
    ah_free(host);
    if (status || !server.value) { ah_track_call(g, o, "SamConnect", ah_ntstatus_name(g.arena, static_cast<ULONG>(status))); if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: SamConnect %s: %lu\n", o->text("dNSHostName"), static_cast<ULONG>(status)); } return; }
    ah_sam_domain *domains = nullptr, **tail = &domains;
    ULONG context = 0;
    do {
        ah_sam_rid *rows = nullptr; ULONG count = 0, previous = context;
        status = api.domains(server.value, &context, reinterpret_cast<void **>(&rows), 0xffffffffUL, &count);
        if (status && static_cast<ULONG>(status) != 0x105U) { ah_track_call(g, o, "GetDomains", ah_ntstatus_name(g.arena, static_cast<ULONG>(status))); if (rows) api.release(rows); return; }
        if (count > 100000 || (count && !rows)) { if (rows) api.release(rows); return; }
        for (ULONG i = 0; i < count && !g.arena.failed; ++i) {
            PSID sid = nullptr;
            if (api.lookup_domain(server.value, &rows[i].name, &sid) || !sid) { if (sid) api.release(sid); continue; }
            ah_sam_domain *item = g.arena.make<ah_sam_domain>();
            if (item) {
                item->name = ah_sam_name(g.arena, rows[i].name); item->sid = ah_sid_from_psid(g.arena, sid);
                size_t size = 8 + static_cast<unsigned char *>(sid)[1] * 4;
                item->binary = item->sid ? g.arena.copy(static_cast<const char *>(sid), size) : nullptr;
                if (item->name && item->sid && item->binary) { *tail = item; tail = &item->next; if (!o->machine_sid&&!ah_eq(item->name, "builtin")) o->machine_sid = item->sid; }
            }
            api.release(sid);
        }
        if (rows) api.release(rows);
        if (status && (!count || previous == context)) return;
    } while (static_cast<ULONG>(status) == 0x105U && !g.arena.failed);
    if(o->machine_sid)ah_cache_machine_sid(o->id,o->machine_sid);
    const bool dc = (ah_integer(o, "userAccountControl") & 0x2000) != 0;
    if (!o->machine_sid) { ah_track_call(g, o, "GetMachineSid", "Unable to get machine sid"); if (ah_host_diagnostics) { BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: GetMachineSid %s failed\n", o->text("dNSHostName")); } return; }
    ah_sam_handle machine(api);
    for (ah_sam_domain *item = domains; item && !machine.value; item = item->next)
        if (ah_eq(item->sid, o->machine_sid)) api.open_domain(server.value, 0x300, item->binary, &machine.value);
    for (ah_sam_domain *item = domains; item && !g.arena.failed; item = item->next) {
        if (dc && !ah_eq(item->name, "builtin")) continue;
        ah_sam_handle domain(api);
        NTSTATUS domain_status = api.open_domain(server.value, 0x300, item->binary, &domain.value);
        if (domain_status || !domain.value) { ah_track_call(g, o, ah_concat(g.arena, "OpenDomain - ", item->name), ah_ntstatus_name(g.arena, static_cast<ULONG>(domain_status))); continue; }
        ULONG alias_context = 0;
        do {
            ah_sam_rid *aliases = nullptr; ULONG count = 0, previous = alias_context;
            status = api.aliases(domain.value, &alias_context, reinterpret_cast<void **>(&aliases), 0xffffffffUL, &count);
            if (status && static_cast<ULONG>(status) != 0x105U) { ah_track_call(g, o, ah_concat(g.arena, "GetAliases - ", item->name), ah_ntstatus_name(g.arena, static_cast<ULONG>(status))); if (aliases) api.release(aliases); break; }
            if (count > 100000 || (count && !aliases)) { if (aliases) api.release(aliases); break; }
            for (ULONG i = 0; i < count && !g.arena.failed; ++i) {
                ah_local_group_info *group = g.arena.make<ah_local_group_info>(); if (!group) break;
                char *base_name = ah_sam_name(g.arena, aliases[i].name);
                group->raw_sid = const_cast<char *>(ah_sid_rid(g.arena, item->sid, aliases[i].rid));
                group->sid = dc && ah_wellknown_kind(group->raw_sid) ? ah_concat(g.arena, g.object_domain(o), "-", group->raw_sid) : const_cast<char *>(ah_sid_rid(g.arena, o->id, aliases[i].rid));
                group->name = dc ? g.arena.copy("IGNOREME") : ah_upper(g.arena, ah_concat(g.arena, base_name, "@", o->text("dNSHostName")));
                group->next = o->local_groups; o->local_groups = group;
                ah_sam_handle alias(api);
                NTSTATUS member_status = api.open_alias(domain.value, 4, aliases[i].rid, &alias.value);
                if (member_status || !alias.value) { const char *error = ah_ntstatus_name(g.arena, static_cast<ULONG>(member_status)); group->failure_reason = ah_concat(g.arena, "SamOpenAliasInDomain failed with status ", error); ah_track_call(g, o, ah_concat(g.arena, "OpenAlias - ", base_name), error); continue; }
                PSID *members = nullptr; ULONG member_count = 0;
                member_status = api.members(alias.value, &members, &member_count);
                if ((member_status && static_cast<ULONG>(member_status) != 0x8000001aU) || (member_count && !members)) { const char *error = ah_ntstatus_name(g.arena, static_cast<ULONG>(member_status)); group->failure_reason = ah_concat(g.arena, "SamGetMembersInAlias failed with status ", error); ah_track_call(g, o, ah_concat(g.arena, "GetMembersInAlias - ", base_name), error); if (members) api.release(members); continue; }
                group->collected = true;
                ah_track_call(g, o, ah_concat(g.arena, "GetMembersInAlias - ", base_name), "Success");
                for (ULONG j = 0; j < member_count && !g.arena.failed; ++j) {
                    char *sid = ah_sid_from_psid(g.arena, members[j]); if (!sid || ah_filtered_sid(sid)) continue;
                    SID_NAME_USE usage = SidTypeUnknown; char *member_name = sid;
                    if (!dc && ah_machine_principal(o, sid) && !ah_wellknown_kind(sid)) {
                        if (!machine.value) continue;
                        const unsigned char *binary = static_cast<unsigned char *>(members[j]);
                        ULONG rid = ah_u32(binary + 8 + 4 * (binary[1] - 1));
                        LSA_UNICODE_STRING *names = nullptr; SID_NAME_USE *uses = nullptr;
                        NTSTATUS lookup_status = api.lookup(machine.value, 1, &rid, &names, &uses);
                        if (!lookup_status && names && uses) { usage = uses[0]; member_name = ah_sam_name(g.arena, names[0]); }
                        if (names) api.release(names);
                        if (uses) api.release(uses);
                        if (lookup_status || !member_name || usage == SidTypeUser) continue;
                    }
                    const char *kind = nullptr;
                    if (ah_local_member_id(g, o, sid, usage, &kind)) ah_add_session(g.arena, &group->members, sid, member_name, 0, 0, usage);
                }
                if (members) api.release(members);
            }
            if (aliases) api.release(aliases);
            if (status && (!count || previous == alias_context)) break;
        } while (static_cast<ULONG>(status) == 0x105U && !g.arena.failed);
    }
}
