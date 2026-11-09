#pragma once
#include "../../../common/output/json.hpp"
#include "../../../common/output/archive_output.hpp"

static const char *ah_ipa_kind(const wchar_t *type) {
    if (ah_weq(type, L"IPADomain")) return "IPA_Domain";
    if (ah_weq(type, L"IPAUser")) return "IPA_User";
    if (ah_weq(type, L"IPAGroup")) return "IPA_Group";
    if (ah_weq(type, L"IPAComputer")) return "IPA_Computer";
    if (ah_weq(type, L"IPAService")) return "IPA_Service";
    if (ah_weq(type, L"IPAPermission")) return "IPA_Permission";
    if (ah_weq(type, L"IPARole")) return "IPA_Role";
    if (ah_weq(type, L"IPACA")) return "IPA_CA";
    if (ah_weq(type, L"IPACertificateTemplate")) return "IPA_CertificateTemplate";
    if (ah_weq(type, L"IPASeLinux")) return "IPA_SELinux";
    if (ah_weq(type, L"Base")) return "Base";
    return nullptr;
}
static bool ah_locked(const ah_object *o) { return ah_eq(o->text("nsaccountlock"), "TRUE"); }
#include "references.hpp"
struct ah_graph final {
    ah_directory &directory;
    ah_arena &arena;
    ah_index dns, sids, hosts, principals;
    ah_object *root = nullptr;
    char *domain = nullptr;
    explicit ah_graph(ah_directory &data) : directory(data), arena(data.arena) {}
    bool init(const wchar_t *base) {
        root = nullptr;
        if (!ah_ipa_resolve_references(directory, dns)) return false;
        size_t principal_count = 0;
        for (ah_object *o = directory.objects; o; o = o->next)
            for (ah_value *v = o->values("krbPrincipalName"); v; v = v->next) ++principal_count;
        char *dn = arena.utf8(base);
        if (!dn) return false;
        ah_buffer name(65536); bool first = true;
        for (const char *p = dn; *p; p = ah_parent(p)) {
            if (ah_prefix(p, "DC=")) {
                if (!first) { AH_TEXT(&name, "."); }
                first = false;
                const char *end = p + 3; while (*end && *end != ',') ++end;
                ah_append(&name, p + 3, static_cast<size_t>(end - p - 3));
            }
        }
        AH_TEXT(&name, "\0");
        if (name.failed) return false;
        domain = ah_upper(arena, name.data);
        if (!domain) return false;
        if (!sids.init(arena, directory.count) ||
            !hosts.init(arena, directory.count) || !principals.init(arena, principal_count)) return false;
        for (ah_object *o = directory.objects; o && !arena.failed; o = o->next) {
            o->kind = ah_ipa_kind(o->type);
            o->exported = !o->auxiliary_only && o->kind && !ah_locked(o);
            if (ah_weq(o->type, L"IPADomain")) {
                if (root) return false;
                root = o;
            }
            o->id = arena.copy(o->text("ipaNTSecurityIdentifier", o->dn));
            if (o->id) for (char *p = o->id; *p; ++p) if (*p == ':') *p = '_';
            if (o->exported && !o->id) return false;
            if (*o->dn) dns.put(o->dn, o);
            if (o->id) sids.put(o->id, o);
            if (ah_weq(o->type, L"IPAComputer")) hosts.put(o->text("fqdn"), o);
            for (ah_value *v = o->values("krbPrincipalName"); v; v = v->next) principals.put(v->data, o);
        }
        if (!root || !root->id || !domain || !*domain || arena.failed) return false;
        if (*root->text("associatedDomain")) domain = ah_upper(arena, root->text("associatedDomain"));
        if (!domain) return false;
        for (ah_object *o = directory.objects; o; o = o->next) o->parent = o->children = o->sibling = nullptr;
        for (ah_object *o = directory.objects; o; o = o->next) {
            o->parent = dns.find(ah_parent(o->dn));
            if (o->parent && o->exported) { o->sibling = o->parent->children; o->parent->children = o; }
        }
        return true;
    }
};
#include "ipa_graph.hpp"

static bool ah_export(ah_directory &directory, const ah_profile *profile, const wchar_t *base,
    char *filename, size_t limit) {
    ah_graph graph(directory);
    if (!graph.init(base)) { BeaconPrintf(CALLBACK_ERROR, "Cannot resolve graph identifiers or domain root"); return false; }
    if (!*filename) filename = ah_default_filename(graph.arena, profile, graph.domain);
    if (!filename) return false;
    char timestamp[16];
    if (!ah_output_timestamp(timestamp)) return false;
    filename = ah_output_name(graph.arena, filename, "zip", timestamp);
    if (!filename) return false;
    ah_zip zip(limit, ah_zip_password);
    ah_buffer json(limit);
    if (!ah_ipa_file(graph, json) || !ah_write_dataset(graph.arena, zip, json, "freeipa_graph", timestamp)) return false;
    if (!ah_no_zip && !zip.download(filename)) return false;
    if (ah_no_zip) BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: %u JSON files ready in Downloads", 1U);
    static const char *kinds[] = {"IPA_User", "IPA_Computer", "IPA_Group", "IPA_Domain", "IPA_Service",
        "IPA_Permission", "IPA_Role", "IPA_CA", "IPA_CertificateTemplate", "IPA_SELinux", "Base"};
    static const char *names[] = {"users", "computers", "groups", "domains", "services", "permissions",
        "roles", "cas", "certtemplates", "selinux", "base"};
    uint64_t counts[sizeof(kinds) / sizeof(kinds[0])] = {};
    for (const ah_object *object = directory.objects; object; object = object->next) {
        if (!object->exported) continue;
        for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i)
            if (ah_eq(object->kind, kinds[i])) { ++counts[i]; break; }
    }
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i)
        if (i < 4 || counts[i]) ah_report_dataset_count(names[i], counts[i]);
    return true;
}
