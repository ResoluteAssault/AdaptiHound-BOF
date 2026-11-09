#pragma once

// Query parameters are owned by the cursor. The connection and security control
// remain owned by the caller; an entry is borrowed until next() or destruction.
class ah_ldap_cursor final {
    struct page_resources final {
        LDAPControlW *request = nullptr, **response = nullptr;
        LDAPMessage *message = nullptr;
        berval *cookie = nullptr;
        void reset() {
            if (cookie) WLDAP32$ber_bvfree(cookie);
            if (response) WLDAP32$ldap_controls_freeW(response);
            if (message) WLDAP32$ldap_msgfree(message);
            if (request) WLDAP32$ldap_control_freeW(request);
            request = nullptr; response = nullptr; message = nullptr; cookie = nullptr;
        }
        ~page_resources() { reset(); }
    } page;
    ah_arena parameters;
    ah_buffer cookie;
    LDAP *ld;
    LDAPControlW *security_control;
    wchar_t *dn = nullptr, *type = nullptr, *filter = nullptr, **attributes = nullptr;
    LDAPMessage *current = nullptr;
    ah_ldap_retry_state retries;
    ULONG scope, status_value = LDAP_SUCCESS;
    unsigned int page_size;
    size_t seen = 0;
    bool optional, ended = false, consumed = false;
    bool entry_failed = false, integrity_failed = false;

    wchar_t *copy(const wchar_t *text) {
        if (!text) return nullptr;
        const size_t length = ah_wlen(text);
        if (length > SIZE_MAX / sizeof(wchar_t) - 1) { parameters.failed = true; return nullptr; }
        auto *result = static_cast<wchar_t *>(parameters.alloc((length + 1) * sizeof(wchar_t)));
        if (result) for (size_t i = 0; i <= length; ++i) result[i] = text[i];
        return result;
    }
    void stop(ULONG status) {
        status_value = status; ended = true; current = nullptr;
        page.reset();
    }
    LDAPMessage *yield() {
        if (seen == SIZE_MAX) { stop(LDAP_DECODING_ERROR); return nullptr; }
        ++seen; consumed = false;
        return current;
    }
    bool fetch() {
        unsigned int empty_pages = 0;
        for (;;) {
            page.reset();
            if (cookie.length > UINT32_MAX) { stop(LDAP_DECODING_ERROR); return false; }
            berval previous = {static_cast<ULONG>(cookie.length), cookie.data};
            ld = ah_ldap_current(ld);
            status_value = WLDAP32$ldap_create_page_controlW(ld, page_size, &previous, TRUE, &page.request);
            if (status_value != LDAP_SUCCESS || !page.request) {
                stop(status_value ? status_value : static_cast<ULONG>(LDAP_LOCAL_ERROR)); return false;
            }
            LDAPControlW *controls[] = {page.request, security_control, nullptr};
            struct l_timeval timeout = {ah_ldap_query_timeout_seconds, 0};
            status_value = ah_ldap_search_retry(ld, dn, scope, filter, attributes, 0, controls,
                nullptr, &timeout, 0, &page.message, true, &retries);
            if (status_value != LDAP_SUCCESS) { stop(status_value); return false; }
            ULONG returned_status = LDAP_SUCCESS;
            status_value = WLDAP32$ldap_parse_resultW(ld, page.message, &returned_status,
                nullptr, nullptr, nullptr, &page.response, FALSE);
            if (status_value == LDAP_SUCCESS) status_value = returned_status;
            if (status_value != LDAP_SUCCESS) { stop(status_value); return false; }
            ULONG total = 0;
            status_value = WLDAP32$ldap_parse_page_controlW(ld, page.response, &total, &page.cookie);
            if (status_value != LDAP_SUCCESS || !page.cookie || (page.cookie->bv_len && !page.cookie->bv_val)) {
                stop(status_value ? status_value : static_cast<ULONG>(LDAP_DECODING_ERROR)); return false;
            }
            cookie.length = 0;
            ah_append(&cookie, page.cookie->bv_val, page.cookie->bv_len);
            if (cookie.failed) { stop(LDAP_NO_MEMORY); return false; }
            current = page.message ? WLDAP32$ldap_first_entry(ld, page.message) : nullptr;
            if (current) return true;
            if (!cookie.length) { stop(LDAP_NO_RESULTS_RETURNED); return false; }
            // A server may return an empty intermediate page. Its opaque cookie
            // still requires another request; it does not indicate completion.
            if (++empty_pages >= 32) { stop(LDAP_DECODING_ERROR); return false; }
        }
    }
public:
    ah_ldap_cursor(LDAP *connection, const ah_query &query, const wchar_t *base,
        const wchar_t *const *attrs, LDAPControlW *security, unsigned int pages,
        const wchar_t *selected_filter = nullptr)
        : parameters(0, 4096), cookie(0, 128), ld(connection), security_control(security),
          scope(query.scope), page_size(pages), optional(query.optional != 0) {
        const wchar_t *selected = selected_filter ? selected_filter : query.filter;
        if (!ld || !query.type || !query.prefix || !base || !selected || !page_size) {
            stop(LDAP_PARAM_ERROR); return;
        }
        const size_t prefix_length = ah_wlen(query.prefix), base_length = ah_wlen(base);
        size_t length = 0;
        if (!ah_size_add(prefix_length, base_length, length) || length > SIZE_MAX / sizeof(wchar_t) - 1) {
            stop(LDAP_NO_MEMORY); return;
        }
        dn = static_cast<wchar_t *>(parameters.alloc((length + 1) * sizeof(wchar_t)));
        if (dn) {
            for (size_t i = 0; i < prefix_length; ++i) dn[i] = query.prefix[i];
            for (size_t i = 0; i <= base_length; ++i) dn[prefix_length + i] = base[i];
        }
        type = copy(query.type); filter = copy(selected);
        if (attrs) {
            size_t count = 0;
            while (attrs[count]) {
                if (count >= SIZE_MAX / sizeof(wchar_t *) - 1) { stop(LDAP_NO_MEMORY); return; }
                ++count;
            }
            attributes = static_cast<wchar_t **>(parameters.alloc((count + 1) * sizeof(wchar_t *)));
            if (attributes) {
                for (size_t i = 0; i < count && !parameters.failed; ++i) attributes[i] = copy(attrs[i]);
                attributes[count] = nullptr;
            }
        }
        if (!dn || !type || !filter || parameters.failed || (attrs && !attributes)) stop(LDAP_NO_MEMORY);
    }
    LDAPMessage *next() {
        if (ended) return nullptr;
        if (current) {
            current = WLDAP32$ldap_next_entry(ld, current);
            if (current) return yield();
            if (!cookie.length) { stop(LDAP_NO_RESULTS_RETURNED); return nullptr; }
        }
        if (!fetch()) return nullptr;
        return yield();
    }
    // Append only the current entry, using the existing ranged-attribute parser.
    // A failed append makes the query incomplete even if subsequent pages succeed.
    int append(ah_directory &data, bool main_producer, bool auxiliary_only, ah_index *existing,
        const ah_ldap_entry_policy &policy, bool *entry_failure = nullptr) {
        if (!current || ended || consumed) {
            entry_failed = true; integrity_failed = true;
            if (entry_failure) *entry_failure = true;
            return 0;
        }
        consumed = true;
        bool integrity = false;
        const int result = ah_entry(data, type, ld, current, main_producer, auxiliary_only, existing, &integrity, policy);
        if (!result) entry_failed = true;
        if (integrity) {
            entry_failed = true; integrity_failed = true;
            if (entry_failure) *entry_failure = true;
        }
        return result && !integrity;
    }
    LDAP *connection() const { return ld; }
    ULONG status() const { return status_value; }
    size_t count() const { return seen; }
    bool complete() const {
        return ended && !entry_failed && (status_value == LDAP_NO_RESULTS_RETURNED ||
            (optional && status_value == LDAP_NO_SUCH_OBJECT));
    }
    bool failed() const { return entry_failed || (ended && !complete()); }
    bool integrity_failure() const { return integrity_failed; }
    ah_ldap_cursor(const ah_ldap_cursor &) = delete;
    ah_ldap_cursor &operator=(const ah_ldap_cursor &) = delete;
};
