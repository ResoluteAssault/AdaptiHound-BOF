#pragma once

static void ah_site_links(ah_graph &g, ah_buffer &b, ah_object *o) {
    AH_TEXT(&b, "["); bool first = true;
    const char *p = o->text("gPLink");
    while (*p) {
        while (*p && *p != '[') ++p;
        if (!*p) break;
        ++p;
        if (!ah_prefix(p, "LDAP://")) break;
        p += 7;
        const char *end = p, *separator = nullptr;
        while (*end && *end != ']') { if (*end == ';') separator = end; ++end; }
        if (!*end || !separator) break;
        uint64_t flags = ah_unsigned(separator + 1);
        const char *id = nullptr, *kind = nullptr;
        if (flags != 1 && flags != 3 && ah_resolve_directory_dn(g, g.arena.copy(p, static_cast<size_t>(separator - p)), &id, &kind)) {
            if (!first) { AH_TEXT(&b, ","); }
            first = false; AH_TEXT(&b, "{\"GUID\":"); ah_string(b, id);
            AH_TEXT(&b, ",\"IsEnforced\":"); if (flags == 2) AH_TEXT(&b, "true}"); else AH_TEXT(&b, "false}");
        }
        p = end + 1;
    }
    AH_TEXT(&b, "]");
}

static void ah_site_node(ah_graph &g, ah_buffer &b, ah_object *o) {
    bool site = ah_weq(o->type, L"sites"), server = ah_weq(o->type, L"siteservers"), subnet = ah_weq(o->type, L"sitesubnets");
    const bool collect_acl = (ah_collection & (AH_ACL | AH_SITE)) != 0;
    const bool collect_props = (ah_collection & (AH_OBJECT_PROPS | AH_SITE)) != 0;
    const bool collect_container = (ah_collection & (AH_CONTAINER | AH_SITE)) != 0;
    AH_TEXT(&b, "{"); ah_fields node(b);
    node.text("ObjectIdentifier", o->id);
    node.key("Properties"); AH_TEXT(&b, "{"); ah_fields props(b);
    const char *account = o->text("name", o->text("cn", "UNKNOWN"));
    const char *owner_domain = g.object_domain(o);
    props.text("domain", owner_domain);
    const char *display = server && *o->text("dNSHostName") ? o->text("dNSHostName") : ah_concat(g.arena, account, "@", owner_domain);
    props.text("name", ah_upper(g.arena, display));
    props.text("distinguishedname", ah_upper(g.arena, o->dn)); props.text("domainsid", g.object_domain_sid(o));
    ah_value *sd = o->values("nTSecurityDescriptor");
    if (collect_props) ah_common_object_properties(g, b, props, o);
    if (collect_acl) {
        props.boolean("doesanyacegrantownerrights", ah_owner_rights(g, o, false)); props.boolean("doesanyinheritedacegrantownerrights", ah_owner_rights(g, o, true));
        props.boolean("isaclprotected", sd && sd->size >= 20 && (ah_u16(reinterpret_cast<unsigned char *>(sd->data) + 2) & 0x1000));
    }
    if (server && collect_props) {
        props.nullable_text("dnshostname", o->text("dNSHostName", nullptr)); props.nullable_text("serverreference", o->text("serverReference", nullptr));
    }
    if (subnet && collect_props) {
        props.nullable_text("cn", o->text("cn", nullptr)); props.nullable_text("siteobject", o->text("siteObject", nullptr));
    }
    if (collect_props) ah_extra_properties(g, b, props, o);
    AH_TEXT(&b, "}");
    node.key("Aces"); if (collect_acl) ah_ad_acl(g, b, o); else AH_TEXT(&b, "[]");
    node.boolean("IsACLProtected", collect_acl && sd && sd->size >= 20 && (ah_u16(reinterpret_cast<unsigned char *>(sd->data) + 2) & 0x1000));
    node.boolean("IsDeleted", false);
    node.key("ContainedBy");
    if (!collect_container) AH_TEXT(&b, "null");
    else if (server) ah_directory_ref(g, b, ah_parent(ah_parent(o->dn)));
    else if (subnet) ah_directory_ref(g, b, o->text("siteObject"));
    else ah_directory_ref(g, b, ah_parent(o->dn));
    if (site) {
        node.key("ChildObjects"); AH_TEXT(&b, "[]");
        node.key("Links"); if (ah_collection & AH_SITE) ah_site_links(g, b, o); else AH_TEXT(&b, "[]");
        node.key("InheritanceHashes"); if (collect_acl) ah_inheritance_hashes(g, b, sd); else AH_TEXT(&b, "[]");
    }
    if (server) {
        node.key("ServerIs"); if (ah_collection & AH_SITE) ah_directory_ref(g, b, o->text("serverReference"), "Computer"); else AH_TEXT(&b, "null");
    }
    AH_TEXT(&b, "}");
}

static bool ah_site_file(ah_graph &g, ah_buffer &b, const wchar_t *type, const char *name) {
    AH_TEXT(&b, "{\"data\":["); unsigned int count = 0;
    for (ah_object *o = g.directory.objects; o && !b.failed && !g.arena.failed; o = o->next) if (ah_output_selected(g, o) && ah_weq(o->type, type)) {
        if (count++) AH_TEXT(&b, ",");
        ah_site_node(g, b, o);
    }
    AH_TEXT(&b, "],\"meta\":{"); ah_fields meta(b);
    meta.text("type", name); meta.number("count", count); meta.number("version", 6); meta.number("methods", ah_collection); meta.text("collectorversion", "AdaptiHound-BOF");
    AH_TEXT(&b, "}}");
    return !b.failed && !g.arena.failed;
}
