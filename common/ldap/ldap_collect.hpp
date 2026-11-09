#pragma once
#include "ldap_entry_policy.hpp"

static wchar_t *ah_range(wchar_t *name, unsigned int *next, int *terminal, unsigned int *start = nullptr) {
    static const wchar_t suffix[] = L";range=";
    for (wchar_t *p = name; *p; ++p) {
        if (*p != ';' || ah_wlen(p) < 9) continue;
        bool match = true;
        for (unsigned int i = 0; i < 7; ++i) {
            wchar_t c = p[i]; if (c >= 'A' && c <= 'Z') c += 32;
            if (c != suffix[i]) { match = false; break; }
        }
        if (!match) continue;
        wchar_t *v = p + 7; unsigned int begin = 0;
        if (*v < '0' || *v > '9') return nullptr;
        while (*v >= '0' && *v <= '9') {
            if (begin > 100000000U) return nullptr;
            begin = begin * 10 + static_cast<unsigned int>(*v++ - '0');
        }
        if (*v++ != '-') return nullptr;
        *terminal = *v == '*'; *next = 0;
        if (*terminal) { if (v[1]) return nullptr; }
        else {
            if (*v < '0' || *v > '9') return nullptr;
            while (*v >= '0' && *v <= '9') {
                if (*next > 100000000U) return nullptr;
                *next = *next * 10 + static_cast<unsigned int>(*v++ - '0');
            }
            if (*v || *next < begin) return nullptr;
            ++*next;
        }
        if (start) *start = begin;
        return p;
    }
    return nullptr;
}

static void ah_values(ah_directory &data, ah_attr *attribute, struct berval **values) {
    for (unsigned int i = 0; values && values[i] && !data.arena.failed; ++i)
        data.value(attribute, values[i]->bv_val, values[i]->bv_len);
}

static int ah_attribute(ah_directory &data, ah_object *object, LDAP *ld, LDAPMessage *entry, wchar_t *dn, wchar_t *name,bool merge_missing=false,bool *integrity_failure=nullptr) {
    unsigned int next = 0, start = 0; int terminal = 0, ok = 1;
    wchar_t *range = ah_range(name, &next, &terminal, &start);
    if (range && start != 0) { if(integrity_failure)*integrity_failure=true;return 0; }
    struct range_name_owner final {
        wchar_t *value = nullptr;
        ~range_name_owner() { ah_free(value); }
    } canonical;
    if (range) {
        const size_t length = static_cast<size_t>(range - name);
        if (length > SIZE_MAX / sizeof(wchar_t) - 1) { data.arena.failed = true; return 0; }
        // Keep the base name independent of descriptors returned by WinLDAP.
        canonical.value = ah_alloc<wchar_t>((length + 1) * sizeof(wchar_t));
        if (!canonical.value) { data.arena.failed = true; return 0; }
        for (size_t i = 0; i < length; ++i) canonical.value[i] = name[i];
        canonical.value[length] = 0;
    }
    wchar_t *base_name = range ? canonical.value : name;
    char *attribute_name = data.arena.utf8(base_name);
    if (!attribute_name) return 0;
    ah_attr *attribute = object->attr(attribute_name);
    if (merge_missing && attribute && attribute->values) return 1;
    struct berval **values = WLDAP32$ldap_get_values_lenW(ld, entry, name);
    if (!attribute) attribute = data.attribute(object, attribute_name);
    ah_values(data, attribute, values);
    if (values) WLDAP32$ldap_value_free_len(values);
    ah_ldap_retry_state ranged_retries;
    while (range && !terminal && !data.arena.failed) {
        size_t n = ah_wlen(base_name) + 64;
        wchar_t *request = ah_alloc<wchar_t>(n * sizeof(wchar_t));
        if (!request) { data.arena.failed = true; break; }
        MSVCRT$_snwprintf(request, n, L"%ls;range=%u-*", base_name, next);
        wchar_t *attrs[] = {request, nullptr}; LDAPMessage *result = nullptr;
        struct l_timeval timeout = {ah_ldap_query_timeout_seconds, 0};
        ULONG status = ah_ldap_search_retry(ld, dn, LDAP_SCOPE_BASE, const_cast<wchar_t *>(L"(objectClass=*)"), attrs, 0, nullptr, nullptr, &timeout, 0, &result,false,&ranged_retries);
        LDAPMessage *item = status == LDAP_SUCCESS && result ? WLDAP32$ldap_first_entry(ld, result) : nullptr;
        BerElement *ber = nullptr;
        wchar_t *actual = item ? WLDAP32$ldap_first_attributeW(ld, item, &ber) : nullptr;
        unsigned int following = 0, returned_start = 0; int last = 0;
        bool same_attribute = false;
        while (actual) {
            wchar_t *actual_range = ah_range(actual, &following, &last, &returned_start);
            same_attribute = actual_range && static_cast<size_t>(actual_range - actual) == ah_wlen(base_name);
            for (size_t i = 0; same_attribute && i < ah_wlen(base_name); ++i) {
                wchar_t x = actual[i], y = base_name[i];
                if (x >= 'A' && x <= 'Z') x += 32;
                if (y >= 'A' && y <= 'Z') y += 32;
                if (x != y) same_attribute = false;
            }
            if (same_attribute) break;
            WLDAP32$ldap_memfreeW(actual);
            actual = WLDAP32$ldap_next_attributeW(ld, item, ber);
        }
        if(status!=LDAP_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: %ls range starting %u failed (LDAP %u)", base_name, next, status);
            ok=0;
        }
        else if (!same_attribute || returned_start != next || (!last && following <= next)) {
            BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: %ls range starting %u returned unexpected attribute %ls", base_name, next, actual ? actual : L"<missing>");
            ok=0;
            if(integrity_failure)*integrity_failure=true;
        }
        else {
            values = WLDAP32$ldap_get_values_lenW(ld, item, actual);
            ah_values(data, attribute, values);
            if (values) WLDAP32$ldap_value_free_len(values);
            next = following; terminal = last;
        }
        if (actual) WLDAP32$ldap_memfreeW(actual);
        if (ber) WLDAP32$ber_free(ber, 0);
        if (result) WLDAP32$ldap_msgfree(result);
        ah_free(request);
        if (!ok) break;
    }
    return ok && !data.arena.failed;
}

static int ah_entry(ah_directory &data, const wchar_t *type, LDAP *ld, LDAPMessage *entry, bool main_producer, bool auxiliary_only,ah_index *existing,bool *integrity_failure, const ah_ldap_entry_policy &policy) {
    int ok = 1;
    wchar_t *dn = WLDAP32$ldap_get_dnW(ld, entry);
    if (!dn) { data.arena.failed = true; return 0; }
    char *utf8 = data.arena.utf8(dn);
    if (utf8 && main_producer && policy.skip && policy.skip(utf8)) {
        WLDAP32$ldap_memfreeW(dn); return 1;
    }
    ah_object *object=utf8&&existing?existing->find(utf8):nullptr;
    bool merge=object!=nullptr;
    if(!object&&utf8){object=data.add(type,utf8);if(object)object->auxiliary_only=auxiliary_only;}
    BerElement *ber = nullptr;
    wchar_t *name = object ? WLDAP32$ldap_first_attributeW(ld, entry, &ber) : nullptr;
    while (name && !data.arena.failed) {
        if (!ah_attribute(data, object, ld, entry, dn, name,merge,integrity_failure)) ok = 0;
        WLDAP32$ldap_memfreeW(name);
        name = WLDAP32$ldap_next_attributeW(ld, entry, ber);
    }
    if (name) WLDAP32$ldap_memfreeW(name);
    if (ber) WLDAP32$ber_free(ber, 0);
    if (policy.classify) policy.classify(data, object, type);
    WLDAP32$ldap_memfreeW(dn);
    return ok && !data.arena.failed;
}

static wchar_t *ah_root(LDAP *ld, const wchar_t *attribute) {
    wchar_t *attrs[] = {(wchar_t *)attribute, NULL}; LDAPMessage *result = NULL;
    struct l_timeval timeout = {ah_ldap_query_timeout_seconds, 0}; wchar_t *out = NULL;
    ULONG status = ah_ldap_search_retry(ld, const_cast<wchar_t *>(L""), LDAP_SCOPE_BASE, const_cast<wchar_t *>(L"(objectClass=*)"), attrs, 0, NULL, NULL, &timeout, 0, &result);
    LDAPMessage *entry = status == LDAP_SUCCESS && result ? WLDAP32$ldap_first_entry(ld, result) : NULL;
    struct berval **values = entry ? WLDAP32$ldap_get_values_lenW(ld, entry, (wchar_t *)attribute) : NULL;
    if (values && values[0]) {

        struct berval *chosen = values[0];
        if (attribute[0] == 'n') {
            unsigned int matches = 0;
            for (unsigned int i = 0; values[i]; ++i) {
                char *s = values[i]->bv_val;
                if (values[i]->bv_len >= 3 && (s[0] == 'd' || s[0] == 'D') && (s[1] == 'c' || s[1] == 'C') && s[2] == '=') { chosen = values[i]; ++matches; }
            }
            if (matches != 1) chosen = NULL;
        }
        if (chosen) {
            char *s = ah_alloc((size_t)chosen->bv_len + 1);
            if (s) { for (ULONG i = 0; i < chosen->bv_len; ++i) s[i] = chosen->bv_val[i]; out = ah_wide(s); ah_free(s); }
        }
    }
    if (values) WLDAP32$ldap_value_free_len(values);
    if (result) WLDAP32$ldap_msgfree(result);
    return out;
}

static int ah_dataset_page(ah_directory &data, LDAP *ld, const ah_query *q, wchar_t *base, const wchar_t *const *attrs, LDAPControlW *security_control, unsigned int page_size, const wchar_t *filter, bool main_producer, bool auxiliary_only, bool quiet,ah_index *existing,const ah_ldap_entry_policy &policy,bool *entry_failure=nullptr) {
    size_t n = ah_wlen(q->prefix) + ah_wlen(base) + 1;
    wchar_t *dn = ah_alloc<wchar_t>(n * sizeof(wchar_t));
    if (!dn) { data.arena.failed = true; return 0; }
    MSVCRT$_snwprintf(dn, n, L"%ls%ls", q->prefix, base);
    ULONG status = LDAP_SUCCESS; unsigned int count = 0; int ok = 1;
    ah_buffer cookie(0,128);
    ah_ldap_retry_state query_retries;
    while (!data.arena.failed) {
        struct page_resources final {
            LDAPControlW *request=nullptr,**response=nullptr;
            LDAPMessage *message=nullptr;berval *cookie=nullptr;
            ~page_resources(){
                if(cookie)WLDAP32$ber_bvfree(cookie);
                if(response)WLDAP32$ldap_controls_freeW(response);
                if(message)WLDAP32$ldap_msgfree(message);
                if(request)WLDAP32$ldap_control_freeW(request);
            }
        } page;
        if(cookie.length>UINT32_MAX){data.arena.failed=true;break;}
        berval previous={static_cast<ULONG>(cookie.length),cookie.data};
        ld=ah_ldap_current(ld);
        status=WLDAP32$ldap_create_page_controlW(ld,page_size,&previous,TRUE,&page.request);
        if(status!=LDAP_SUCCESS||!page.request){if(!status)status=LDAP_LOCAL_ERROR;break;}
        LDAPControlW *page_controls[]={page.request,security_control,nullptr};
        struct l_timeval timeout={ah_ldap_query_timeout_seconds,0};

        status=ah_ldap_search_retry(ld,dn,q->scope,const_cast<wchar_t *>(filter),const_cast<wchar_t **>(attrs),0,page_controls,nullptr,&timeout,0,&page.message,true,&query_retries);
        if(status!=LDAP_SUCCESS)break;
        ULONG returned_status=LDAP_SUCCESS;
        status=WLDAP32$ldap_parse_resultW(ld,page.message,&returned_status,nullptr,nullptr,nullptr,&page.response,FALSE);
        if(status==LDAP_SUCCESS)status=returned_status;
        if(status!=LDAP_SUCCESS)break;
        ULONG total=0;
        status=WLDAP32$ldap_parse_page_controlW(ld,page.response,&total,&page.cookie);
        if(status!=LDAP_SUCCESS||!page.cookie||(page.cookie->bv_len&&!page.cookie->bv_val)){
            if(!status)status=LDAP_DECODING_ERROR;
            break;
        }
        cookie.length=0;
        ah_append(&cookie,page.cookie->bv_val,page.cookie->bv_len);
        if(cookie.failed){data.arena.failed=true;break;}
        unsigned int entries=0;
        for(LDAPMessage *item=page.message?WLDAP32$ldap_first_entry(ld,page.message):nullptr;item&&!data.arena.failed;item=WLDAP32$ldap_next_entry(ld,item)){
            ++count;++entries;
            if(!ah_entry(data,q->type,ld,item,main_producer,auxiliary_only,existing,entry_failure,policy))ok=0;
        }
        if(!cookie.length||!entries){status=LDAP_NO_RESULTS_RETURNED;break;}
    }
    if (status != LDAP_NO_RESULTS_RETURNED && !(q->optional && status == LDAP_NO_SUCH_OBJECT)) ok = 0;
    if (!ok) BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: %ls: %u objects (LDAP %u)", q->type, count, status);
    else if (!quiet) ah_log_telemetry("AdaptiHound: %ls: %u objects (LDAP %u)", q->type, count, status);
    ah_free(dn);
    return ok;
}
