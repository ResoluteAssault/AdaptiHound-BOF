#pragma once

#include "properties.hpp"

struct ah_ipa_path { const ah_object *object; const ah_ipa_path *parent; };

struct ah_ipa_command_set {
    struct item { const char *value; item *next; };
    item *first = nullptr, *last = nullptr;
    bool contains(const char *value) const {
        for (item *p = first; p; p = p->next) {
            const char *a = p->value, *b = value;
            while (*a && *a == *b) { ++a; ++b; }
            if (*a == *b) return true;
        }
        return false;
    }
    void insert(ah_graph &g, const char *value) {
        if (contains(value)) return;
        item *entry = g.arena.make<item>();
        if (!entry) return;
        entry->value = value;
        if (last) last->next = entry; else first = entry;
        last = entry;
    }
    bool any(const ah_ipa_command_set *exclude = nullptr) const {
        for (item *p = first; p; p = p->next) if (!exclude || !exclude->contains(p->value)) return true;
        return false;
    }
    void write(ah_buffer &out, const ah_ipa_command_set *exclude = nullptr) const {
        AH_TEXT(&out, "["); bool comma = false;
        for (item *p = first; p; p = p->next) if (!exclude || !exclude->contains(p->value)) {
            if (comma) { AH_TEXT(&out, ","); } comma = true; ah_string(out, p->value);
        }
        AH_TEXT(&out, "]");
    }
};
static void ah_ipa_commands(ah_graph &g, const char *dn, ah_ipa_command_set &set, const ah_ipa_path *path = nullptr, unsigned int depth = 0) {
    ah_object *o = g.dns.find(dn);
    for (const ah_ipa_path *p = path; p; p = p->parent) if (p->object == o) return;
    if (depth > 32) { g.arena.failed = true; return; }
    ah_ipa_path here = {o, path};
    ah_value *commands = o ? o->values("sudoCmd") : nullptr;
    if (!commands && o) commands = o->values("ipaSudoCmd");
    if (commands) {
        for (ah_value *v = commands; v; v = v->next) set.insert(g, v->data);
    } else if (o && o->values("member")) {
        for (ah_value *v = o->values("member"); v && !g.arena.failed; v = v->next) ah_ipa_commands(g, v->data, set, &here, depth + 1);
    } else set.insert(g, dn);
}

class ah_ipa_edges final {
    struct edge { const char *from, *to, *kind; ah_object *rule; edge *next, *bucket_next; };
    ah_graph &g;
    edge **buckets = nullptr, *first = nullptr, *last = nullptr;
    size_t capacity = 0;
    static uint64_t hash(const char *a, const char *b, const char *c) {
        uint64_t h = 1469598103934665603ULL;
        const char *parts[] = {a,b,c};
        for (const char *p : parts) { while (*p) { h ^= static_cast<unsigned char>(*p++); h *= 1099511628211ULL; } h ^= 0xff; h *= 1099511628211ULL; }
        return h;
    }
public:
    explicit ah_ipa_edges(ah_graph &graph) : g(graph) {
        capacity = 16; while (capacity < g.directory.count * 4) capacity *= 2;
        buckets = static_cast<edge **>(g.arena.alloc(capacity * sizeof(edge *)));
    }
    bool has(ah_object *from, ah_object *to, const char *kind) const {
        if (!buckets || !from || !to) return false;
        size_t bucket = hash(from->id, to->id, kind) & (capacity - 1);
        for (edge *e = buckets[bucket]; e; e = e->bucket_next) if (ah_eq(e->from, from->id) && ah_eq(e->to, to->id) && ah_eq(e->kind, kind)) return true;
        return false;
    }
    void raw(const char *from, const char *to, const char *kind, ah_object *rule = nullptr, bool unique = true) {
        if (!buckets || !from || !to || !*from || !*to || ah_eq(from, to)) return;
        size_t bucket = hash(from, to, kind) & (capacity - 1);
        if (unique) for (edge *e = buckets[bucket]; e; e = e->bucket_next) if (ah_eq(e->from, from) && ah_eq(e->to, to) && ah_eq(e->kind, kind)) return;
        edge *e = g.arena.make<edge>(); if (!e) return;
        e->from = from; e->to = to; e->kind = kind; e->rule = rule;
        e->bucket_next = buckets[bucket]; buckets[bucket] = e;
        if (last) last->next = e; else first = e; last = e;
    }
    void add(ah_object *from, ah_object *to, const char *kind, ah_object *rule = nullptr, bool unique = true) {
        if (from && to && from->exported && to->exported) raw(from->id, to->id, kind, rule, unique);
    }
    void write(ah_buffer &b) const {
        AH_TEXT(&b, "["); bool comma = false;
        for (edge *e = first; e && !b.failed; e = e->next) {
            if (e->kind[0] == '_') continue;
            if (comma) { AH_TEXT(&b, ","); } comma = true;
            AH_TEXT(&b, "{\"start\":{\"match_by\":\"id\",\"value\":"); ah_string(b, e->from);
            AH_TEXT(&b, "},\"end\":{\"match_by\":\"id\",\"value\":"); ah_string(b, e->to);
            AH_TEXT(&b, "},\"kind\":"); ah_string(b, e->kind);
            if (e->rule) {
                AH_TEXT(&b, ",\"properties\":{"); ah_fields props(b);
                const bool sudo = ah_eq(e->kind, "IPA_CanSUDO");
                ah_ipa_rule_properties(b, props, e->rule, sudo);
                if (sudo) {
                    ah_ipa_command_set allow, deny;
                    for (ah_value *v = e->rule->values("memberAllowCmd"); v; v = v->next) ah_ipa_commands(g, v->data, allow);
                    for (ah_value *v = e->rule->values("memberDenyCmd"); v; v = v->next) ah_ipa_commands(g, v->data, deny);
                    if (allow.any(&deny)) { props.key("allow_cmd"); allow.write(b, &deny); }
                    if (deny.any()) { props.key("deny_cmd"); deny.write(b); }
                }
                AH_TEXT(&b, "}");
            }
            AH_TEXT(&b, "}");
        }
        AH_TEXT(&b, "]");
    }
};

template <typename Visitor>
static void ah_ipa_targets(ah_graph &g, ah_object *rule, const char *category, const char *member, const char *kind, Visitor visitor, bool persons_only = false) {
    if (ah_eq(rule->text(category), "all")) {
        for (ah_object *o = g.directory.objects; o && !g.arena.failed; o = o->next)
            if (o->exported && !o->placeholder && ah_eq(o->kind, kind) && (!persons_only || ah_has(o, "objectClass", "person"))) visitor(o);
    } else {
        for (ah_value *v = rule->values(member); v && !g.arena.failed; v = v->next)
            if (ah_object *o = g.dns.find(v->data)) if (o->exported) visitor(o);
    }
}
static bool ah_ipa_rule_service(ah_object *rule, bool sudo) {
    if (ah_eq(rule->text("serviceCategory"), "all")) return true;
    const char *prefix = sudo ? "cn=Sudo,cn=hbacservicegroups,cn=hbac," : "cn=sshd,cn=hbacservices,cn=hbac,";
    for (ah_value *v = rule->values("memberService"); v; v = v->next) if (ah_prefix(v->data, prefix)) return true;
    return false;
}
static void ah_ipa_mark_hbac(ah_graph &g, ah_ipa_edges &edges, ah_object *user, ah_object *host) {
    edges.add(user, host, "_sudo_hbac");
    for (ah_value *h = host->values("member"); h; h = h->next) {
        ah_object *target = g.dns.find(h->data);
        edges.add(user, target, "_sudo_hbac");
        for (ah_value *u = user->values("member"); u; u = u->next) edges.add(g.dns.find(u->data), target, "_sudo_hbac");
    }
}
static bool ah_ipa_hbac_access(ah_graph &g, const ah_ipa_edges &edges, ah_object *user, ah_object *host) {
    if (edges.has(user, host, "_sudo_hbac")) return true;
    for (ah_value *h = host->values("member"); h; h = h->next) {
        ah_object *target = g.dns.find(h->data);
        if (edges.has(user, target, "_sudo_hbac")) return true;
        for (ah_value *u = user->values("member"); u; u = u->next) if (edges.has(g.dns.find(u->data), target, "_sudo_hbac")) return true;
    }
    return false;
}
static void ah_ipa_node(ah_graph &g, ah_buffer &b, ah_object *o) {
    AH_TEXT(&b, "{\"id\":"); ah_string(b, o->id); AH_TEXT(&b, ",\"kinds\":["); ah_string(b, o->kind);
    if (o->placeholder) {
        AH_TEXT(&b, "],\"properties\":{"); ah_fields props(b);
        props.text("name", ah_concat(g.arena, ah_upper(g.arena, o->text("cn")), "@", g.domain));
        props.text("domain", g.domain); props.text("distinguishedname", o->dn); props.text("environmentid", g.root->id);
        AH_TEXT(&b, "}}"); return;
    }

    const bool netgroup = ah_eq(o->kind, "IPA_Group") && ah_has(o, "objectClass", "ipaNisNetGroup");
    const bool hbac = ah_eq(o->kind, "IPA_Group") && ah_has(o, "objectClass", "ipaHBACRule");
    if (netgroup) AH_TEXT(&b, ",\"IPA_NetGroup\"");
    if (hbac) AH_TEXT(&b, ",\"IPA_HBACRule\"");
    AH_TEXT(&b, "],\"properties\":{"); ah_fields props(b);
    const char *name = o->dn;
    if (o->values("krbPrincipalName")) name = o->text("krbPrincipalName");
    else if (o->values("sn") || o->values("cn") || o->values("uid")) name = ah_concat(g.arena, o->text("sn", o->text("cn", o->text("uid"))), "@", g.domain);
    else if (o->values("ipaOriginalUid")) name = o->text("ipaOriginalUid");
    else if (o->values("associatedDomain")) name = o->text("associatedDomain");
    name = ah_upper(g.arena, name);
    if (netgroup) name = ah_concat(g.arena, "Net Group: ", name);
    if (hbac) name = ah_concat(g.arena, "HBAC: ", name);
    props.text("name", name); props.text("distinguishedname", o->dn); props.text("environmentid", g.root->id); props.text("domain", g.domain);
    if (o == g.root) props.boolean("collected", true);
    if (o == g.root || (ah_eq(o->kind, "IPA_Group") && (ah_eq(o->text("cn"), "admins") || ah_eq(o->text("cn"), "trust admins") || ah_prefix(ah_parent(o->dn), "cn=sysaccounts,cn=etc,")))) props.boolean("highvalue", true);
    if (ah_eq(o->kind, "IPA_User")) {
        props.boolean("PasswordAuthAllow", !o->values("ipaUserAuthType") || ah_has(o, "ipaUserAuthType", "password"));
        if (o->values("userCertificate") || o->values("userCertificate;binary")) props.boolean("HaveCert", true);
    }
    if (netgroup || hbac) props.boolean("NetGroup", true);
    if (ah_eq(o->kind, "IPA_CertificateTemplate")) props.boolean("Enabled", true);
    uint64_t flags = ah_unsigned(o->text("krbTicketFlags"));
    if (o->values("krbTicketFlags")) { props.boolean("unconstraineddelegation", (flags & 0x100000) != 0); props.boolean("ipakrbokasdelegate", (flags & 0x100000) != 0); props.boolean("ipakrboktoauthasdelegate", (flags & 0x200000) != 0); }
    for (ah_attr *a = o->attributes; a; a = a->next) {
        if (!a->values || ah_eq(a->name, "objectClass") || ah_eq(a->name, "member") || ah_eq(a->name, "memberOf") || ah_eq(a->name, "userCertificate") || ah_eq(a->name, "userCertificate;binary") || ah_eq(a->name, "dn") || ah_eq(a->name, "domain") || ah_eq(a->name, "name") || (ah_eq(a->name, "nsaccountlock") && !ah_eq(o->kind, "IPA_User"))) continue;
        props.key(a->name);
        ah_ipa_property(b, a);
    }
    AH_TEXT(&b, "}}");
}
static bool ah_ipa_file(ah_graph &g, ah_buffer &b) {
    ah_ipa_edges edges(g);
    static const char *membership[] = {"member", "memberUser", "memberHost", "ipaExternalMember"};
    static const char *rights[] = {"memberManager", "managedBy", "ipaAllowedToPerform;read_keys", "ipaAllowedToPerform;write_keys", "ipaAllowedToPerform;write_delegation"};
    static const char *kinds[] = {"IPA_AddMember", "IPA_Owns", "IPA_ReadKerberosKey", "IPA_ForceChangePassword", "IPA_AddRBCD"};
    for (ah_object *o = g.directory.objects; o && !g.arena.failed; o = o->next) if (o->exported) {
        for (const char *attribute : membership) for (ah_value *v = o->values(attribute); v; v = v->next) {
            ah_object *member = g.dns.find(v->data);
            if (member) {
                edges.add(member, o, "IPA_MemberOf");
                if (ah_prefix(ah_parent(member->dn), "cn=permissions,cn=pbac,") || ah_prefix(ah_parent(member->dn), "cn=privileges,cn=pbac,")) edges.add(member, g.root, "_permission_reference");
            }
            else if (ah_eq(attribute, "ipaExternalMember") && ah_prefix(v->data, "S-1-")) edges.raw(v->data, o->id, "IPA_MemberOf");
        }
        for (ah_value *v = o->values("memberOf"); v; v = v->next) {
            ah_object *target = g.dns.find(v->data); edges.add(o, target, "IPA_MemberOf");
            if (target && (ah_prefix(ah_parent(target->dn), "cn=permissions,cn=pbac,") || ah_prefix(ah_parent(target->dn), "cn=privileges,cn=pbac,"))) edges.add(target, g.root, "_permission_reference");
        }
        for (unsigned int i = 0; i < 5; ++i) for (ah_value *v = o->values(rights[i]); v; v = v->next) {
            ah_object *target = g.dns.find(v->data); edges.add(target, o, kinds[i]);
            if (target && (ah_prefix(ah_parent(target->dn), "cn=permissions,cn=pbac,") || ah_prefix(ah_parent(target->dn), "cn=privileges,cn=pbac,"))) edges.add(target, g.root, "_permission_reference");
        }
        for (ah_value *v = o->values("memberPrincipal"); v; v = v->next) edges.add(g.principals.find(v->data), o, "IPA_AllowedToDelegate");
    }
    for (ah_object *o = g.directory.objects; o && !g.arena.failed; o = o->next)
        if (edges.has(o, g.root, "_permission_reference") && (ah_eq(o->text("cn"), "Replication Managers") || ah_eq(o->text("cn"), "Replication Administrators") || ah_eq(o->text("cn"), "Add Replication Agreements") || ah_eq(o->text("cn"), "Modify Replication Agreements"))) edges.add(o, g.root, "IPA_DSync");

    for (ah_object *rule = g.directory.objects; rule && !g.arena.failed; rule = rule->next) if (ah_weq(rule->type, L"hbac_rule") && ah_eq(rule->text("ipaEnabledFlag"), "TRUE") && !ah_eq(rule->text("accessRuleType"), "deny")) {
        bool ssh = ah_ipa_rule_service(rule, false), sudo = ah_ipa_rule_service(rule, true);
        ah_ipa_targets(g, rule, "userCategory", "memberUser", "IPA_User", [&](ah_object *user) {
            ah_ipa_targets(g, rule, "hostCategory", "memberHost", "IPA_Computer", [&](ah_object *host) {
                if (ssh) edges.add(user, host, "IPA_CanSSH", rule, false);
                if (sudo) ah_ipa_mark_hbac(g, edges, user, host);
            });
        });
    }
    for (ah_object *rule = g.directory.objects; rule && !g.arena.failed; rule = rule->next) {
        if (ah_weq(rule->type, L"sudo_rule") && ah_eq(rule->text("ipaEnabledFlag"), "TRUE")) {
            ah_ipa_targets(g, rule, "userCategory", "memberUser", "IPA_User", [&](ah_object *user) {
                ah_ipa_targets(g, rule, "hostCategory", "memberHost", "IPA_Computer", [&](ah_object *host) { if (ah_ipa_hbac_access(g, edges, user, host)) edges.add(user, host, "IPA_CanSUDO", rule, false); });
            }, ah_eq(rule->text("userCategory"), "all"));
        } else if (ah_weq(rule->type, L"ca_acl") && ah_eq(rule->text("ipaEnabledFlag"), "TRUE")) {
            for (ah_value *v = rule->values("ipaMemberCertProfile"); v; v = v->next) {
                ah_object *profile = g.dns.find(v->data);
                ah_ipa_targets(g, rule, "userCategory", "memberUser", "IPA_User", [&](ah_object *o) { edges.add(o, profile, "IPA_Enroll", nullptr, false); });
                ah_ipa_targets(g, rule, "hostCategory", "memberHost", "IPA_Computer", [&](ah_object *o) { edges.add(o, profile, "IPA_Enroll", nullptr, false); });
                ah_ipa_targets(g, rule, "serviceCategory", "memberService", "IPA_Service", [&](ah_object *o) { edges.add(o, profile, "IPA_Enroll", nullptr, false); });
            }
        } else if (ah_weq(rule->type, L"S4U2Proxy")) {
            for (ah_value *source = rule->values("memberPrincipal"); source; source = source->next) {
                ah_object *from = g.principals.find(source->data);
                for (ah_value *target = rule->values("ipaAllowedTarget"); target; target = target->next) {
                    ah_object *group = g.dns.find(target->data);
                    if (group) for (ah_value *principal = group->values("memberPrincipal"); principal; principal = principal->next) edges.add(from, g.principals.find(principal->data), "IPA_AllowedToDelegate");
                }
            }
        } else if (ah_weq(rule->type, L"IPATrust")) {
            const char *sid = rule->text("ipaNTTrustedDomainSID", rule->dn);
            edges.raw(sid, g.root->id, "IPA_TrustedBy");
            if (ah_unsigned(rule->text("ipaNTTrustType")) == 2) edges.raw(g.root->id, sid, "IPA_TrustedBy");
        }
    }
    AH_TEXT(&b, "{\"metadata\":{\"source_kind\":\"IPAHound\"},\"graph\":{\"nodes\":["); bool first = true;
    for (ah_object *o = g.directory.objects; o && !g.arena.failed && !b.failed; o = o->next) if (o->exported) { if (!first) { AH_TEXT(&b, ","); } first = false; ah_ipa_node(g, b, o); if (!b.failed && !g.arena.failed) ah_observe_object_completed(); }
    AH_TEXT(&b, "],\"edges\":"); edges.write(b); AH_TEXT(&b, "}}");
    return !b.failed && !g.arena.failed;
}
