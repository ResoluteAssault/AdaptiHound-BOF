#pragma once
#include "batch_cursor.hpp"

static ah_object *ah_batch_find_dn(ah_directory &data, const char *dn) {
    if (!dn || !*dn) return nullptr;
    for (ah_object *object = data.objects; object; object = object->next)
        if (ah_eq(object->dn, dn)) return object;
    return nullptr;
}
static const wchar_t *ah_batch_copy_type(ah_directory &data, const wchar_t *type) {
    if (!type) { data.arena.failed = true; return nullptr; }
    const size_t length = ah_wlen(type);
    if (length > SIZE_MAX / sizeof(wchar_t) - 1) { data.arena.failed = true; return nullptr; }
    auto *copy = static_cast<wchar_t *>(data.arena.alloc((length + 1) * sizeof(wchar_t)));
    if (copy) for (size_t i = 0; i <= length; ++i) copy[i] = type[i];
    return copy;
}
static ah_object *ah_batch_clone_object_into(ah_directory &data, const ah_object &source,
    bool auxiliary_only, ah_object *existing) {
    if (!source.dn || !source.type) { data.arena.failed = true; return nullptr; }
    ah_object *object = existing;
    if (!object) {
        const wchar_t *type = ah_batch_copy_type(data, source.type);
        object = type ? data.add(type, source.dn) : nullptr;
        if (!object) return nullptr;
        object->auxiliary_only = auxiliary_only;
        object->explicit_target = !auxiliary_only && source.explicit_target;
        object->synthesized_dns_name = source.synthesized_dns_name;
    } else if (!auxiliary_only) {
        // A producer can promote a support object. Loading support cannot demote
        // an existing producer object, particularly the current domain root.
        object->auxiliary_only = false;
        object->explicit_target = object->explicit_target || source.explicit_target;
    }
    for (const ah_attr *attribute = source.attributes; attribute && !data.arena.failed; attribute = attribute->next) {
        ah_attr *target = object->attr(attribute->name);
        if (target && target->values) continue;
        if (!target) target = data.attribute(object, attribute->name);
        if (!target) return nullptr;
        for (const ah_value *value = attribute->values; value && !data.arena.failed; value = value->next)
            if (!data.value(target, value->data, value->size)) return nullptr;
    }
    return data.arena.failed ? nullptr : object;
}
static ah_object *ah_batch_clone_object(ah_directory &data, const ah_object &source, bool auxiliary_only = true) {
    return ah_batch_clone_object_into(data, source, auxiliary_only, ah_batch_find_dn(data, source.dn));
}
static bool ah_batch_clone_support(ah_directory &data, const ah_directory &support) {
    if (&data == &support) return false;
    for (const ah_object *source = support.objects; source && !data.arena.failed; source = source->next)
        if (!ah_batch_clone_object(data, *source)) return false;
    return !data.arena.failed;
}

// The temporary index grows without retaining old slot arrays in the batch's
// arena. Keys and objects are borrowed only until this helper returns.
class ah_batch_dependency_index final {
    ah_arena arena;
    ah_index index;
    size_t reserved = 0;
public:
    ah_batch_dependency_index() : arena(0, 4096) {}
    bool refresh(ah_directory &data) {
        if (reserved && data.count <= reserved) return true;
        if (data.count > SIZE_MAX / 2) { data.arena.failed = true; return false; }
        reserved = data.count < 128 ? 256 : data.count * 2;
        arena.reset();
        if (!index.init(arena, reserved)) { data.arena.failed = true; return false; }
        for (ah_object *object = data.objects; object && !arena.failed; object = object->next)
            if (object->dn && *object->dn) index.put(object->dn, object);
        if (arena.failed) { data.arena.failed = true; return false; }
        return true;
    }
    ah_object *find(const char *dn) const { return index.find(dn); }
    bool add(ah_directory &data, ah_object *object) {
        if (!refresh(data)) return false;
        index.put(object->dn, object);
        if (arena.failed) { data.arena.failed = true; return false; }
        return true;
    }
};
static bool ah_batch_gpo_scope(const ah_object *object) {
    return !object->auxiliary_only && object->dn && *object->dn && *object->text("gPLink") &&
        (ah_weq(object->type, L"domains") || ah_weq(object->type, L"ous"));
}
static bool ah_batch_gpo_descendant(const char *dn, const char *ancestor) {
    const size_t length = ah_len(dn), ancestor_length = ah_len(ancestor);
    return length > ancestor_length && dn[length - ancestor_length - 1] == ',' &&
        ah_eq(dn + length - ancestor_length, ancestor);
}
static bool ah_batch_gpo_dependencies(ah_directory &data, LDAP *ld, unsigned int pages, int methods) {
    if (!(methods & AH_GPO_LOCAL_GROUP)) return !data.arena.failed;
    ah_batch_dependency_index existing;
    if (!existing.refresh(data)) return false;
    const wchar_t *attributes[] = {L"objectSid", L"objectGUID", L"distinguishedName", L"objectClass",
        L"sAMAccountType", L"userAccountControl", L"dNSHostName", L"sAMAccountName", L"name", L"cn", nullptr};
    const ah_query query = {L"computers", L"",
        L"(&(sAMAccountType=805306369)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))",
        LDAP_SCOPE_SUBTREE, 0};
    for (ah_object *container = data.objects; container && !data.arena.failed; container = container->next) {
        if (!ah_batch_gpo_scope(container)) continue;
        bool covered = false;
        for (ah_object *other = data.objects; other && !covered; other = other->next)
            if (other != container && ah_batch_gpo_scope(other) && ah_batch_gpo_descendant(container->dn, other->dn)) covered = true;
        if (covered) continue;
        wchar_t *base = ah_wide(container->dn);
        if (!base) { data.arena.failed = true; return false; }
        ah_ldap_cursor cursor(ld, query, base, attributes, nullptr, pages);
        ah_free(base);
        while (cursor.next()) {
            ah_directory entry(0, 4096);
            if (!cursor.append(entry, false, true, nullptr, ah_ad_entry_policy)) return false;
            for (ah_object *source = entry.objects; source; source = source->next) {
                ah_object *object = ah_batch_clone_object_into(data, *source, true, existing.find(source->dn));
                if (!object || !existing.add(data, object)) return false;
            }
        }
        if (!cursor.complete()) {
            BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: GPO computer dependencies incomplete for %s (LDAP %u)", container->dn, cursor.status());
            return false;
        }
    }
    return !data.arena.failed;
}
