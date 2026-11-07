#pragma once
static int ah_dataset(ah_directory &data, LDAP *ld, const ah_query *q, wchar_t *base, const wchar_t *const *attrs, int sd, unsigned int page_size,
    bool main_producer = false, bool partition = false, bool auxiliary_only = false, bool quiet = false,bool merge_existing=false) {
    ah_index existing;
    if(auxiliary_only||merge_existing) {
        if(!existing.init(data.arena,data.count))return 0;
        for(ah_object *o=data.objects;o;o=o->next)existing.put(o->dn,o);
    }
    const bool has_custom=main_producer&&(*ah_ldap_filter||ah_ldap_filter_present);
    wchar_t *custom = has_custom ? ah_ldap_filter_normalize(ah_ldap_filter) : nullptr;
    if (has_custom && !custom) { data.arena.failed = true; return 0; }
    wchar_t *combined = nullptr;
    const wchar_t *selected = q->filter;
    if (custom) {
        size_t size = ah_wlen(q->filter) + ah_wlen(custom) + 4;
        combined = ah_alloc<wchar_t>(size * sizeof(wchar_t));
        if (combined) MSVCRT$_snwprintf(combined, size, L"(&%ls%ls)", q->filter, custom);
        ah_free(custom);
        if (!combined) { data.arena.failed = true; return 0; }
        selected = combined;
    }
    int ok = 1;
    if (main_producer && partition && ah_partition_queries) {
        size_t length = ah_wlen(selected) + 32;
        wchar_t *part = ah_alloc<wchar_t>(length * sizeof(wchar_t));
        if (!part) { data.arena.failed = true; ok = 0; }
        else for (unsigned int i = 0; i < 256 && !data.arena.failed; ++i) {
            MSVCRT$_snwprintf(part, length, L"(&%ls(objectGUID=\\%02x*))", selected, i);
            bool entry_failure=false;
            const int complete=ah_dataset_page(data, ld, q, base, attrs, sd?&ah_ad_security_control:nullptr, page_size, part, main_producer, auxiliary_only, quiet,auxiliary_only||merge_existing?&existing:nullptr,ah_ad_entry_policy,&entry_failure);
            if(!complete)ok=0;

            if(entry_failure)break;
        }
        ah_free(part);
    } else ok = ah_dataset_page(data, ld, q, base, attrs, sd?&ah_ad_security_control:nullptr, page_size, selected, main_producer, auxiliary_only, quiet,auxiliary_only||merge_existing?&existing:nullptr,ah_ad_entry_policy);
    ah_free(combined); return ok && !data.arena.failed;
}
