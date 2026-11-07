#pragma once
#include "../../../common/ldap/directory.hpp"

struct ah_object {
    const wchar_t *type;
    char *dn, *id;
    const char *kind;
    ah_attr *attributes;
    ah_object *next, *parent, *children, *sibling;
    bool exported, auxiliary_only, placeholder;
    ah_attr *attr(const char *name) const {
        for (ah_attr *a = attributes; a; a = a->next) if (ah_eq(a->name, name)) return a;
        return nullptr;
    }
    ah_value *values(const char *name) const { ah_attr *a = attr(name); return a ? a->values : nullptr; }
    const char *text(const char *name, const char *fallback = "") const { ah_value *v = values(name); return v ? v->data : fallback; }
};
struct ah_directory_state {};
#include "../../../common/ldap/directory_store.hpp"
