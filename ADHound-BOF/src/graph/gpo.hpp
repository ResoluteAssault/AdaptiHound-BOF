#pragma once

static ah_object *ah_resolve_linked_gpo(ah_graph &, const char *);
static bool ah_resolve_directory_account_sid(ah_graph &, const char *, const char *, const char **);

struct ah_gpo_action {
    int target, operation, rid;
    char *sid;
    SID_NAME_USE usage;
    ah_gpo_action *next;
};
struct ah_gpo_action_set { ah_session_info *restricted, *memberof, *local; };
struct ah_gpo_computer { ah_object *object; ah_gpo_computer *next; };
struct ah_gpo_cache_entry {
    ah_object *gpo;
    ah_gpo_action *actions;
    ah_gpo_cache_entry *next;
};

static char *ah_gpo_trim(char *value) {
    while (*value && static_cast<unsigned char>(*value) <= 32) ++value;
    size_t n = ah_len(value);
    while (n && static_cast<unsigned char>(value[n - 1]) <= 32) value[--n] = 0;
    return value;
}

static char *ah_gpo_path(ah_graph &g, ah_object *gpo, const wchar_t *, const char *suffix) {
    const char *base = gpo->text("gPCFileSysPath");
    return *base ? ah_concat(g.arena, base, suffix) : nullptr;
}

static char *ah_read_gpo_file(ah_graph &g, ah_object *gpo, const wchar_t *dc, const char *suffix) {
    char *path = ah_gpo_path(g, gpo, dc, suffix);
    if (!path) return nullptr;
    wchar_t *wide = ah_wide(path);
    if (!wide) return nullptr;
    HANDLE file = KERNEL32$CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ah_free(wide);
    if (file == INVALID_HANDLE_VALUE) return nullptr;
    LARGE_INTEGER size = {};
    if (!KERNEL32$GetFileSizeEx(file, &size) || size.QuadPart < 0 || static_cast<uint64_t>(size.QuadPart) > SIZE_MAX) { KERNEL32$CloseHandle(file); return nullptr; }
    size_t length = static_cast<size_t>(size.QuadPart), allocation = 0;
    if (!ah_size_add(length, 3, allocation)) { KERNEL32$CloseHandle(file); return nullptr; }
    char *data = ah_alloc(allocation);
    if (!data) { KERNEL32$CloseHandle(file); return nullptr; }
    size_t offset = 0;
    bool ok = true;
    while (offset < length) {
        DWORD read = 0, wanted = static_cast<DWORD>(length - offset > 1048576 ? 1048576 : length - offset);
        if (!KERNEL32$ReadFile(file, data + offset, wanted, &read, nullptr) || !read || read > wanted) { ok = false; break; }
        offset += read;
    }
    KERNEL32$CloseHandle(file);
    if (!ok || offset != length) { ah_free(data); return nullptr; }
    data[length] = data[length + 1] = data[length + 2] = 0;
    const unsigned char *bytes = reinterpret_cast<unsigned char *>(data);
    bool utf16le = length >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe;
    bool utf16be = length >= 2 && bytes[0] == 0xfe && bytes[1] == 0xff;
    if (utf16le || utf16be) {
        if (length & 1) { ah_free(data); return nullptr; }
        size_t units = (length - 2) / 2, unicode_units = 0, unicode_bytes = 0;
        // WideCharToMultiByte uses signed 32-bit character counts, including
        // the terminator when -1 is passed for its input length.
        if (units >= static_cast<size_t>(0x7fffffffU) || !ah_size_add(units, 1, unicode_units) || !ah_size_multiply(unicode_units, sizeof(wchar_t), unicode_bytes)) { ah_free(data); return nullptr; }
        wchar_t *unicode = ah_alloc<wchar_t>(unicode_bytes);
        if (!unicode) { ah_free(data); return nullptr; }
        for (size_t i = 0; i < units; ++i) {
            unsigned char a = bytes[2 + 2 * i], b = bytes[3 + 2 * i];
            unicode[i] = static_cast<wchar_t>(utf16le ? (a | b << 8) : (b | a << 8));
        }
        unicode[units] = 0;
        int needed = KERNEL32$WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, unicode, -1, nullptr, 0, nullptr, nullptr);
        char *converted = needed > 0 ? ah_alloc(static_cast<size_t>(needed)) : nullptr;
        if (converted && !KERNEL32$WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, unicode, -1, converted, needed, nullptr, nullptr)) { ah_free(converted); converted = nullptr; }
        ah_free(unicode); ah_free(data); return converted;
    }

    if (length >= 3 && bytes[0] == 0xef && bytes[1] == 0xbb && bytes[2] == 0xbf)
        for (size_t i = 0; i <= length - 3; ++i) data[i] = data[i + 3];
    return data;
}

static bool ah_gpo_sid_bytes(const char *sid, unsigned char (&out)[68], size_t &length) {
    if (!ah_prefix(sid, "S-1-")) return false;
    const char *p = sid + 4;
    uint64_t authority = 0;
    if (*p < '0' || *p > '9') return false;
    while (*p >= '0' && *p <= '9') {
        unsigned int digit = static_cast<unsigned int>(*p++ - '0');
        if (authority > (0xffffffffffffULL - digit) / 10) return false;
        authority = authority * 10 + digit;
    }
    out[0] = 1; out[1] = 0;
    for (unsigned int i = 0; i < 6; ++i) out[2 + i] = static_cast<unsigned char>(authority >> ((5 - i) * 8));
    while (*p) {
        if (*p++ != '-' || out[1] == 15 || *p < '0' || *p > '9') return false;
        uint64_t value = 0;
        while (*p >= '0' && *p <= '9') {
            unsigned int digit = static_cast<unsigned int>(*p++ - '0');
            if (value > (0xffffffffULL - digit) / 10) return false;
            value = value * 10 + digit;
        }
        for (unsigned int i = 0; i < 4; ++i) out[8 + 4 * out[1] + i] = static_cast<unsigned char>(value >> (i * 8));
        ++out[1];
    }
    length = 8 + 4 * static_cast<size_t>(out[1]);
    return true;
}

static bool ah_resolve_gpo_account(ah_graph &g, const char *account, char **sid, SID_NAME_USE *usage, const char *gpo_domain = nullptr) {
    while (*account == ' ' || *account == '\t' || *account == '*') ++account;
    if (!*account) return false;
    if (ah_prefix(account, "S-1-")) {
        unsigned char binary[68]; size_t length = 0;
        if (!ah_gpo_sid_bytes(account, binary, length)) return false;
        if (ah_builtin(account)) {
            const char *domain = ah_eq(account, "S-1-5-9") ? g.forest_domain() : gpo_domain && *gpo_domain ? gpo_domain : g.domain;
            const char *kind = ah_wellknown_kind(account);
            *sid = ah_concat(g.arena, domain, "-", account);
            *usage = ah_eq(kind, "User") ? SidTypeUser : ah_eq(kind, "Computer") ? SidTypeComputer : SidTypeGroup;
            return *sid != nullptr;
        }
        const char *resolved_id=nullptr,*kind=nullptr;
        if(!ah_resolve_directory_sid(g,account,&resolved_id,&kind))return false;
        *usage=ah_eq(kind,"User")?SidTypeUser:ah_eq(kind,"Computer")?SidTypeComputer:SidTypeGroup;
        *sid=g.arena.copy(resolved_id);
        return *sid!=nullptr;
    }
    const char *domain = gpo_domain && *gpo_domain ? gpo_domain : g.domain;
    const char *user = account;
    for (const char *p = account; *p; ++p) if (*p == '\\') {
        domain = g.arena.copy(account, static_cast<size_t>(p - account)); user = p + 1;
        const char *end = user; while (*end && *end != '\\') ++end;
        user = g.arena.copy(user, static_cast<size_t>(end - user)); break;
    }
    if (!domain || !user || !*user) return false;
    for (int machine = 0; machine < 2; ++machine) {
        const char *candidate = machine ? ah_concat(g.arena, user, "$") : user;
        const char *qualified = candidate ? ah_concat(g.arena, domain, "\\", candidate) : nullptr;
        ah_object *known = qualified ? g.accounts.find(qualified) : nullptr;
        if (!known && ah_eq(domain, g.domain) && candidate) known = g.accounts.find(candidate);
        const char *resolved_id = known ? known->id : nullptr;
        if (!resolved_id && candidate) ah_resolve_directory_account_sid(g, candidate, domain, &resolved_id);
        if (!resolved_id) continue;
        const char *kind = known ? known->kind : ah_resolved_sid_kind(g, resolved_id);
        *usage = ah_eq(kind, "User") ? SidTypeUser : ah_eq(kind, "Computer") ? SidTypeComputer : ah_eq(kind, "Group") ? SidTypeGroup : SidTypeUnknown;
        *sid = ah_builtin(resolved_id) ? ah_concat(g.arena, ah_eq(resolved_id, "S-1-5-9") ? g.forest_domain() : domain, "-", resolved_id) : g.arena.copy(resolved_id);
        return *sid != nullptr;
    }
    return false;
}

static void ah_gpo_add_action(ah_arena &arena, ah_gpo_action **actions, int target, int operation, int rid, const char *sid, SID_NAME_USE usage) {
    if (!sid || !*sid) return;
    ah_gpo_action *action = arena.make<ah_gpo_action>();
    if (!action) return;
    action->target = target; action->operation = operation; action->rid = rid;
    action->sid = arena.copy(sid); action->usage = usage;
    while (*actions) actions = &(*actions)->next;
    *actions = action;
}

static void ah_gpo_account_action(ah_graph &g, ah_gpo_action **actions, int target, int operation, int rid, const char *account, bool preserve_sid = false, const char *gpo_domain = nullptr) {
    char *sid = nullptr; SID_NAME_USE usage = SidTypeGroup;
    if (ah_resolve_gpo_account(g, account, &sid, &usage, gpo_domain)) ah_gpo_add_action(g.arena, actions, target, operation, rid, preserve_sid ? account : sid, usage);
}

static int ah_gpo_builtin_rid(const char *sid) {
    if (ah_eq(sid, "S-1-5-32-544")) return 544;
    if (ah_eq(sid, "S-1-5-32-555")) return 555;
    if (ah_eq(sid, "S-1-5-32-562")) return 562;
    if (ah_eq(sid, "S-1-5-32-580")) return 580;
    return 0;
}

static void ah_parse_gpo_template(ah_graph &g, ah_gpo_action **actions, char *data, const char *gpo_domain = nullptr) {
    bool group_section = false;
    for (char *line = data; line && *line;) {
        char *next = line;
        while (*next && *next != '\n' && *next != '\r') ++next;
        if (*next) { char newline = *next; *next++ = 0; if ((newline == '\r' && *next == '\n') || (newline == '\n' && *next == '\r')) ++next; }
        line = ah_gpo_trim(line);
        if (*line == '[') { group_section = ah_eq(line, "[Group Membership]"); line = next; continue; }
        if (!group_section || !*line || *line == ';') { line = next; continue; }
        char *separator = line;
        while (*separator && *separator != '=') ++separator;
        if (!*separator) { line = next; continue; }
        *separator = 0;
        char *key = ah_gpo_trim(line), *value = ah_gpo_trim(separator + 1);
        while (*key == '*') ++key;
        size_t key_length = ah_len(key);
        bool members = key_length >= 9 && ah_eq(key + key_length - 9, "__Members");
        bool memberof = key_length >= 10 && ah_eq(key + key_length - 10, "__MemberOf");
        if (!members && !memberof) { line = next; continue; }
        char *suffix = key + key_length - (members ? 9 : 10);
        *suffix = 0;
        key = ah_gpo_trim(key);
        int target_rid = ah_gpo_builtin_rid(key);
        for (char *account = value; *account;) {
            char *end = account;
            while (*end && *end != ',') ++end;
            if (*end) *end++ = 0;
            account = ah_gpo_trim(account);
            while (*account == '*') ++account;
            if (members) {
                if (target_rid == 544 || target_rid == 555 || target_rid == 562 || target_rid == 580)
                    ah_gpo_account_action(g, actions, 0, 0, target_rid, account, false, gpo_domain);
            } else {
                int rid = ah_gpo_builtin_rid(account);
                if (rid) ah_gpo_account_action(g, actions, 1, 0, rid, key, false, gpo_domain);
            }
            account = end;
        }
        line = next;
    }
}

static const char *ah_xml_find(const char *start, const char *needle) {
    size_t length = ah_len(needle);
    for (const char *p = start; *p; ++p) {
        size_t i = 0;
        while (i < length && p[i] && p[i] == needle[i]) ++i;
        if (i == length) return p;
        if (!p[i]) return nullptr;
    }
    return nullptr;
}

static const char *ah_xml_tag(const char *start, const char *name) {
    const char *p = start;
    size_t length = ah_len(name);
    while ((p = ah_xml_find(p, name))) {
        char end = p[length];
        if (!end || end == '>' || end == '/' || static_cast<unsigned char>(end) <= 32) return p;
        p += length;
    }
    return nullptr;
}

static bool ah_xml_attr(const char *tag, const char *name, char *out, size_t capacity) {
    if (!capacity) return false;
    out[0] = 0;
    struct output_guard {
        char *data; bool ok = false;
        ~output_guard() { if (!ok) data[0] = 0; }
    } result{out};
    size_t name_length = ah_len(name);
    for (const char *p = tag; *p && *p != '>'; ++p) {
        if (*p == '\'' || *p == '"') {
            char quote = *p++;
            while (*p && *p != quote) ++p;
            if (!*p) return false;
            continue;
        }
        if (static_cast<unsigned char>(*p) > 32) continue;
        while (p[1] && static_cast<unsigned char>(p[1]) <= 32) ++p;
        if (!ah_prefix(p + 1, name)) continue;
        const char *value = p + 1 + name_length;
        while (*value && static_cast<unsigned char>(*value) <= 32) ++value;
        if (*value++ != '=') continue;
        while (*value && static_cast<unsigned char>(*value) <= 32) ++value;
        char quote = *value++;
        if (quote != '\'' && quote != '"') continue;
        size_t used = 0;
        while (*value && *value != quote) {
            uint32_t codepoint = static_cast<unsigned char>(*value++);
            if (codepoint == '&') {
                const char *entity = value, *end = value;
                while (*end && *end != ';' && end - entity < 16) ++end;
                if (*end != ';') return false;
                size_t n = static_cast<size_t>(end - entity);
                if (n == 3 && ah_prefix(entity, "amp")) codepoint = '&';
                else if (n == 2 && ah_prefix(entity, "lt")) codepoint = '<';
                else if (n == 2 && ah_prefix(entity, "gt")) codepoint = '>';
                else if (n == 4 && ah_prefix(entity, "quot")) codepoint = '"';
                else if (n == 4 && ah_prefix(entity, "apos")) codepoint = '\'';
                else if (n > 1 && *entity == '#') {
                    ++entity; unsigned int base = 10; codepoint = 0;
                    if (*entity == 'x' || *entity == 'X') { base = 16; ++entity; }
                    if (entity == end) return false;
                    for (; entity < end; ++entity) {
                        unsigned int digit = *entity >= '0' && *entity <= '9' ? static_cast<unsigned int>(*entity - '0') :
                            *entity >= 'a' && *entity <= 'f' ? static_cast<unsigned int>(*entity - 'a' + 10) :
                            *entity >= 'A' && *entity <= 'F' ? static_cast<unsigned int>(*entity - 'A' + 10) : 255;
                        if (digit >= base || codepoint > (0x10ffffU - digit) / base) return false;
                        codepoint = codepoint * base + digit;
                    }
                    if (!codepoint || (codepoint >= 0xd800 && codepoint <= 0xdfff)) return false;
                } else return false;
                value = end + 1;
                unsigned int count = codepoint < 0x80 ? 1 : codepoint < 0x800 ? 2 : codepoint < 0x10000 ? 3 : 4;
                if (used + count >= capacity) return false;
                if (count == 1) out[used++] = static_cast<char>(codepoint);
                else {
                    out[used++] = static_cast<char>((count == 2 ? 0xc0 : count == 3 ? 0xe0 : 0xf0) | (codepoint >> ((count - 1) * 6)));
                    for (unsigned int i = count - 1; i; --i) out[used++] = static_cast<char>(0x80 | ((codepoint >> ((i - 1) * 6)) & 0x3f));
                }
            } else {
                if (used + 1 >= capacity) return false;
                out[used++] = static_cast<char>(codepoint);
            }
        }
        if (*value != quote) return false;
        out[used] = 0;
        result.ok = true;
        return true;
    }
    return false;
}

static int ah_gpo_xml_rid(const char *sid, const char *name) {
    if (int rid = ah_gpo_builtin_rid(sid)) return rid;
    if (name) {
        if (ah_eq(name, "Administrators")) return 544;
        if (ah_eq(name, "Remote Desktop Users")) return 555;
        if (ah_eq(name, "Distributed COM Users")) return 562;
        if (ah_eq(name, "Remote Management Users")) return 580;
    }
    return 0;
}

static void ah_parse_gpo_xml(ah_graph &g, ah_gpo_action **actions, char *data, const char *gpo_domain = nullptr) {
    const char *groups = ah_xml_tag(data, "<Groups");
    char disabled[16] = {};
    if (groups && ah_xml_attr(groups, "disabled", disabled, sizeof(disabled)) && ah_eq(disabled, "1")) return;
    const char *group = data;
    while ((group = ah_xml_tag(group, "<Group"))) {
        const char *end = ah_xml_find(group, "</Group>");
        if (!end) break;
        const char *properties = ah_xml_tag(group, "<Properties");
        if (!properties || properties >= end) { group = end; continue; }
        char action[16] = {}, sid[256] = {}, name[256] = {};
        ah_xml_attr(properties, "action", action, sizeof(action));
        if (!ah_eq(action, "u")) { group = end; continue; }
        ah_xml_attr(properties, "groupSid", sid, sizeof(sid));
        ah_xml_attr(properties, "groupName", name, sizeof(name));
        int rid = ah_gpo_xml_rid(sid, name);
        if (!rid) { group = end; continue; }
        char flag[16] = {};
        if (ah_xml_attr(properties, "deleteAllUsers", flag, sizeof(flag)) && ah_eq(flag, "1")) ah_gpo_add_action(g.arena, actions, 2, 2, rid, "S-1-0", SidTypeUser);
        if (ah_xml_attr(properties, "deleteAllGroups", flag, sizeof(flag)) && ah_eq(flag, "1")) ah_gpo_add_action(g.arena, actions, 2, 3, rid, "S-1-0", SidTypeGroup);
        const char *member = properties;
        while ((member = ah_xml_tag(member, "<Member")) && member < end) {
            char member_action[16] = {}, member_sid[256] = {}, member_name[256] = {};
            ah_xml_attr(member, "action", member_action, sizeof(member_action));
            ah_xml_attr(member, "sid", member_sid, sizeof(member_sid));
            ah_xml_attr(member, "name", member_name, sizeof(member_name));
            int operation = ah_eq(member_action, "ADD") ? 0 : 1;
            if (*member_sid) ah_gpo_account_action(g, actions, 2, operation, rid, member_sid, true, gpo_domain);
            if (*member_name) ah_gpo_account_action(g, actions, 2, operation, rid, member_name, false, gpo_domain);
            member += 7;
        }
        group = end;
    }
}

static void ah_collect_affected_computers(ah_graph &g, ah_object *container, ah_gpo_change *changes) {
    if (g.gpo_index_ready) {
        ah_session_info **tail = &changes->affected_computers;
        while (*tail) tail = &(*tail)->next;

        for (ah_gpo_computer *entry = container->gpo_computers; entry; entry = entry->next) {
            ah_session_info *member = g.arena.make<ah_session_info>();
            if (!member) return;
            member->sid = g.arena.copy(entry->object->id);
            member->name = g.arena.copy(entry->object->text("dNSHostName"));
            *tail = member; tail = &member->next;
        }
        return;
    }
    for (ah_object *computer = g.directory.objects; computer; computer = computer->next) {
        if (!ah_eq(computer->kind, "Computer")) continue;

        size_t computer_length=ah_len(computer->dn),container_length=ah_len(container->dn);
        if(computer_length>container_length&&computer->dn[computer_length-container_length-1]==','&&ah_eq(computer->dn+computer_length-container_length,container->dn)) {
            ah_session_info *member = g.arena.make<ah_session_info>();
            if (!member) continue;
            member->sid = g.arena.copy(computer->id); member->name = g.arena.copy(computer->text("dNSHostName"));
            member->next = changes->affected_computers; changes->affected_computers = member;
        }
    }
}

static void ah_gpo_apply_to_sets(ah_arena &arena, ah_gpo_action_set (&sets)[4], ah_gpo_action *actions) {
    bool replaced[4][2] = {};
    for (ah_gpo_action *action = actions; action; action = action->next) {
        int index = action->rid == 544 ? 0 : action->rid == 555 ? 1 : action->rid == 562 ? 2 : 3;
        ah_gpo_action_set &set = sets[index];
        if (action->target < 2) {
            ah_session_info **list = action->target == 0 ? &set.restricted : &set.memberof;

            if (!replaced[index][action->target]) { *list = nullptr; replaced[index][action->target] = true; }
            ah_add_session(arena, list, action->sid, action->sid, 0, 0, action->usage);
        } else if (action->operation == 0) ah_add_session(arena, &set.local, action->sid, action->sid, 0, 0, action->usage);
        else {
            ah_session_info **current = &set.local;
            while (*current) {
                bool remove = action->operation == 1 ? ah_eq((*current)->sid, action->sid) : action->operation == 2 ? (*current)->usage == SidTypeUser : (*current)->usage == SidTypeGroup || (*current)->usage == SidTypeAlias || (*current)->usage == SidTypeWellKnownGroup;
                if (!remove) { current = &(*current)->next; continue; }
                *current = (*current)->next;
            }
        }
    }
}

static void ah_gpo_finish(ah_arena &arena, ah_gpo_change *changes, ah_gpo_action_set (&sets)[4]) {
    for (int i = 0; i < 4; ++i) {
        ah_session_info *final = nullptr;
        for (ah_session_info *p = sets[i].memberof; p; p = p->next) ah_add_session(arena, &final, p->sid, p->sid, 0, 0, p->usage);
        for (ah_session_info *p = sets[i].restricted ? sets[i].restricted : sets[i].local; p; p = p->next)
            ah_add_session(arena, &final, p->sid, p->sid, 0, 0, p->usage);
        if (i == 0) changes->local_admins = final;
        else if (i == 1) changes->remote_desktop_users = final;
        else if (i == 2) changes->dcom_users = final;
        else changes->psremote_users = final;
    }
}

static ah_gpo_action *ah_gpo_cached_actions(ah_graph &g, ah_object *gpo, const wchar_t *dc) {
    for (ah_gpo_cache_entry *p = g.gpo_cache; p; p = p->next) if (p->gpo == gpo) return p->actions;
    ah_gpo_cache_entry *cached = g.arena.make<ah_gpo_cache_entry>();
    if (!cached) return nullptr;
    cached->gpo = gpo; cached->next = g.gpo_cache; g.gpo_cache = cached;
    const char *flags = gpo->text("flags");
    if (!*gpo->text("gPCFileSysPath") || ah_eq(flags, "2") || ah_eq(flags, "3")) return nullptr;
    const char *domain = g.object_domain(gpo);
    char *xml = ah_read_gpo_file(g, gpo, dc, "\\Machine\\Preferences\\Groups\\Groups.xml");
    if (xml) { ah_parse_gpo_xml(g, &cached->actions, xml, domain); ah_free(xml); }
    char *inf = ah_read_gpo_file(g, gpo, dc, "\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf");
    if (inf) { ah_parse_gpo_template(g, &cached->actions, inf, domain); ah_free(inf); }
    return cached->actions;
}

static bool ah_prepare_gpo_output(ah_graph &g, const wchar_t *dc) {
    g.gpo_index_ready = false;
    for (ah_object *object = g.directory.objects; object; object = object->next) object->gpo_computers = nullptr;
    if (!(ah_collection & AH_GPO_LOCAL_GROUP)) return true;

    for (ah_object *computer = g.directory.objects; computer && !g.arena.failed; computer = computer->next) {
        if (!ah_eq(computer->kind, "Computer")) continue;
        for (const char *dn = ah_parent(computer->dn); *dn; dn = ah_parent(dn)) {
            ah_object *container = g.dns.find(dn);
            if (!container || (!ah_eq(container->kind, "Domain") && !ah_eq(container->kind, "OU")) ||
                !*container->text("gPLink") || !ah_output_selected(g, container)) continue;
            ah_gpo_computer *entry = g.arena.make<ah_gpo_computer>();
            if (!entry) return false;
            entry->object = computer; entry->next = container->gpo_computers; container->gpo_computers = entry;
        }
    }
    if (g.arena.failed) return false;

    for (ah_object *container = g.directory.objects; container && !g.arena.failed; container = container->next) {
        if (!container->gpo_computers) continue;
        for (int pass = 0; pass < 2; ++pass) {
            uint64_t wanted = pass == 0 ? 0 : 2;
            const char *p = container->text("gPLink");
            while (*p) {
                while (*p && *p != '[') ++p;
                if (!*p) break;
                ++p;
                if (!ah_prefix(p, "LDAP://")) break;
                p += 7;
                const char *end = p, *separator = nullptr;
                while (*end && *end != ']') { if (*end == ';') separator = end; ++end; }
                if (!*end || !separator) break;
                if (ah_unsigned(separator + 1) == wanted) {
                    const char *dn = g.arena.copy(p, static_cast<size_t>(separator - p));
                    if (!dn) return false;
                    ah_object *gpo = ah_resolve_linked_gpo(g, dn);
                    if (gpo && ah_weq(gpo->type, L"gpos")) ah_gpo_cached_actions(g, gpo, dc);
                }
                p = end + 1;
            }
        }
    }
    if (g.arena.failed) return false;
    g.gpo_index_ready = true;
    return true;
}

static void ah_collect_gpo_changes(ah_graph &g, ah_object *container, const wchar_t *dc) {
    ah_gpo_change *changes = g.arena.make<ah_gpo_change>();
    if (!changes) return;
    container->gpo_changes = changes;
    if (!*container->text("gPLink")) return;
    ah_collect_affected_computers(g, container, changes);
    if (!changes->affected_computers) return;
    ah_gpo_action_set sets[4] = {};
    for (int pass = 0; pass < 2; ++pass) {
        uint64_t wanted = pass == 0 ? 0 : 2;
        const char *p = container->text("gPLink");

        while (*p) {
            while (*p && *p != '[') ++p;
            if (!*p) break;
            ++p;
            if (!ah_prefix(p, "LDAP://")) break;
            p += 7;
            const char *end = p, *separator = nullptr;
            while (*end && *end != ']') { if (*end == ';') separator = end; ++end; }
            if (!*end || !separator) break;
            if (ah_unsigned(separator + 1) == wanted) {
                ah_object *gpo = ah_resolve_linked_gpo(g, g.arena.copy(p, static_cast<size_t>(separator - p)));
                if (gpo && ah_weq(gpo->type, L"gpos")) ah_gpo_apply_to_sets(g.arena, sets, ah_gpo_cached_actions(g, gpo, dc));
            }
            p = end + 1;
        }
    }
    ah_gpo_finish(g.arena, changes, sets);
}

static void ah_gpo_member_array(ah_graph &g, ah_buffer &b, ah_session_info *members, bool references) {
    AH_TEXT(&b, "["); bool first = true;
    for (ah_session_info *member = members; member; member = member->next) {
        if(ah_object *known=g.sids.find(member->sid))ah_mark_output_reference(g,known->id);
        else if(ah_builtin(member->sid))ah_mark_output_reference(g,ah_concat(g.arena,ah_eq(member->sid,"S-1-5-9")?g.forest_domain():g.domain,"-",member->sid));
        if (!first) { AH_TEXT(&b, ","); } first = false;
        if (references) ah_ref(b, g.sids.find(member->sid));
        else if (ah_builtin(member->sid)) ah_ref(b, member->sid, ah_wellknown_kind(member->sid));
        else if (ah_object *known = g.sids.find(member->sid)) ah_ref(b, known);
        else ah_ref(b, member->sid, member->usage == SidTypeUser ? "User" : member->usage == SidTypeComputer ? "Computer" : member->usage == SidTypeUnknown ? "Base" : "Group");
    }
    AH_TEXT(&b, "]");
}

static void ah_gpo_changes_result(ah_graph &g, ah_buffer &b, ah_object *o) {
    ah_gpo_change *changes = o->gpo_changes;
    AH_TEXT(&b, "{\"AffectedComputers\":");
    if (changes) ah_gpo_member_array(g, b, changes->affected_computers, true); else AH_TEXT(&b, "[]");
    AH_TEXT(&b, ",\"DcomUsers\":"); if (changes) ah_gpo_member_array(g, b, changes->dcom_users, false); else AH_TEXT(&b, "[]");
    AH_TEXT(&b, ",\"LocalAdmins\":"); if (changes) ah_gpo_member_array(g, b, changes->local_admins, false); else AH_TEXT(&b, "[]");
    AH_TEXT(&b, ",\"PSRemoteUsers\":"); if (changes) ah_gpo_member_array(g, b, changes->psremote_users, false); else AH_TEXT(&b, "[]");
    AH_TEXT(&b, ",\"RemoteDesktopUsers\":"); if (changes) ah_gpo_member_array(g, b, changes->remote_desktop_users, false); else AH_TEXT(&b, "[]");
    AH_TEXT(&b, "}");
}
