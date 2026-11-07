#pragma once

struct ah_ntlm_context {
    CredHandle credential;
    CtxtHandle context;
    bool has_credential = false, has_context = false;
};

struct ah_http_probe_result {
    char status[64];
    bool collected, vulnerable, epa;
    DWORD http_failure_status;
};

static void ah_text_copy(char *destination, const char *source) {
    size_t i = 0;
    for (; source[i] && i + 1 < 64; ++i) destination[i] = source[i];
    destination[i] = 0;
}

static char *ah_base64_encode(const unsigned char *data, size_t size) {
    if (!data || !size) { char *empty = ah_alloc(1); if (empty) empty[0] = 0; return empty; }
    DWORD length = 0;
    if (!CRYPT32$CryptBinaryToStringA(data, static_cast<DWORD>(size), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &length)) return nullptr;
    char *result = ah_alloc(length + 1);
    if (!result) return nullptr;
    if (!CRYPT32$CryptBinaryToStringA(data, static_cast<DWORD>(size), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result, &length)) { ah_free(result); return nullptr; }
    result[length] = 0;
    return result;
}

static unsigned char *ah_base64_decode(const char *text, size_t *size) {
    *size = 0;
    DWORD length = 0;
    if (!CRYPT32$CryptStringToBinaryA(text, 0, CRYPT_STRING_BASE64, nullptr, &length, nullptr, nullptr)) return nullptr;
    unsigned char *result = reinterpret_cast<unsigned char *>(ah_alloc(length ? length : 1));
    if (!result) return nullptr;
    if (!CRYPT32$CryptStringToBinaryA(text, 0, CRYPT_STRING_BASE64, result, &length, nullptr, nullptr)) { ah_free(result); return nullptr; }
    *size = length;
    return result;
}

static void ah_ntlm_free(ah_ntlm_context &context) {
    if (context.has_context) SECUR32$DeleteSecurityContext(&context.context);
    if (context.has_credential) SECUR32$FreeCredentialsHandle(&context.credential);
    context = {};
}

static unsigned char *ah_ntlm_step(ah_ntlm_context &context, const char *spn, const unsigned char *challenge, size_t challenge_size,
                                   size_t &token_size, bool bad_bindings = true, const void *channel_bindings = nullptr, size_t binding_size = 0) {
    token_size = 0;
    if (!spn || !*spn || challenge_size > 65536 || binding_size > 65536 ||
        (channel_bindings && binding_size < sizeof(SEC_CHANNEL_BINDINGS))) return nullptr;
    if (!context.has_credential) {
        if (SECUR32$AcquireCredentialsHandleW(nullptr, const_cast<SEC_WCHAR *>(L"NTLM"), SECPKG_CRED_OUTBOUND, nullptr, nullptr, nullptr, nullptr, &context.credential, nullptr) != SEC_E_OK) return nullptr;
        context.has_credential = true;
    }
    SecBufferDesc input_desc = {}, output_desc = {};
    SecBuffer input[2] = {}, output = {};
    unsigned char binding_data[sizeof(SEC_CHANNEL_BINDINGS) + 4] = {};
    auto *bindings = reinterpret_cast<SEC_CHANNEL_BINDINGS *>(binding_data);
    if (challenge) {
        input[0].cbBuffer = static_cast<unsigned long>(challenge_size); input[0].BufferType = SECBUFFER_TOKEN; input[0].pvBuffer = const_cast<unsigned char *>(challenge);
        if (channel_bindings) {
            input[1].cbBuffer = static_cast<ULONG>(binding_size); input[1].BufferType = SECBUFFER_CHANNEL_BINDINGS; input[1].pvBuffer = const_cast<void *>(channel_bindings);
        } else if (bad_bindings) {
            bindings->cbApplicationDataLength = 4; bindings->dwApplicationDataOffset = sizeof(SEC_CHANNEL_BINDINGS);
            input[1].cbBuffer = sizeof(binding_data); input[1].BufferType = SECBUFFER_CHANNEL_BINDINGS; input[1].pvBuffer = binding_data;
        }
        input_desc = {SECBUFFER_VERSION, (bad_bindings || channel_bindings) ? 2UL : 1UL, input};
    }
    output.BufferType = SECBUFFER_TOKEN; output_desc = {SECBUFFER_VERSION, 1, &output};
    wchar_t *target = ah_wide(spn);
    if (!target) return nullptr;
    unsigned long attributes = 0; TimeStamp expiry = {};
    SECURITY_STATUS status = SECUR32$InitializeSecurityContextW(&context.credential, context.has_context ? &context.context : nullptr, target, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONNECTION, 0, SECURITY_NATIVE_DREP, challenge ? &input_desc : nullptr, 0, &context.context, &output_desc, &attributes, &expiry);
    ah_free(target);
    if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
        if (output.pvBuffer) SECUR32$FreeContextBuffer(output.pvBuffer);
        ah_ntlm_free(context); return nullptr;
    }
    context.has_context = true;
    unsigned char *token = nullptr;
    if (output.pvBuffer && output.cbBuffer && output.cbBuffer <= 65536) {
        token = ah_alloc<unsigned char>(output.cbBuffer);
        if (token) {
            for (size_t i = 0; i < output.cbBuffer; ++i) token[i] = static_cast<unsigned char *>(output.pvBuffer)[i];
            token_size = output.cbBuffer;
        }
    }
    if (output.pvBuffer) SECUR32$FreeContextBuffer(output.pvBuffer);
    return token;
}

static char *ah_ntlm_token(ah_ntlm_context &context, const char *spn, const unsigned char *challenge, size_t challenge_size,
                           const void *bindings = nullptr, size_t binding_size = 0) {
    size_t token_size = 0;
    unsigned char *raw = ah_ntlm_step(context, spn, challenge, challenge_size, token_size, true, bindings, binding_size);
    if (!raw) return nullptr;
    char *token = ah_base64_encode(raw, token_size); ah_free(raw);
    return token;
}

class ah_http_connection final {
    HINTERNET session = nullptr, connection = nullptr, request = nullptr;
    char failure[64] = {};
    bool failed(const char *stage, DWORD error) {
        ah_text_copy(failure, stage);
        size_t used = ah_len(failure);
        if (used + 1 < sizeof(failure)) failure[used++] = ':';
        char digits[16]; const char *number = ah_decimal(digits + sizeof(digits), error);
        for (size_t i = 0; number[i] && used + 1 < sizeof(failure); ++i) failure[used++] = number[i];
        failure[used] = 0; return false;
    }
    bool failed(const char *stage) { return failed(stage, KERNEL32$GetLastError()); }
    bool option(DWORD name, void *value, DWORD size, const char *stage) {
        return WINHTTP$WinHttpSetOption(request, name, value, size) != FALSE || failed(stage);
    }
public:
    ah_http_connection(const char *host, uint16_t port, const char *path, bool secure) {
        session = WINHTTP$WinHttpOpen(L"AdaptiHound/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!session) { failed("HttpOpenFailed"); return; }
        if (!WINHTTP$WinHttpSetTimeouts(session, 5000, 5000, 5000, 5000)) {
            failed("HttpTimeoutOptionsFailed");
            WINHTTP$WinHttpCloseHandle(session); session = nullptr; return;
        }
        wchar_t *wide_host = ah_wide(host), *wide_path = ah_wide(path);
        if (wide_host && wide_path) {
            connection = WINHTTP$WinHttpConnect(session, wide_host, port, 0);
            if (!connection) failed("HttpConnectFailed");
            else {
                request = WINHTTP$WinHttpOpenRequest(connection, L"GET", wide_path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
                if (!request) failed("HttpOpenRequestFailed");
            }
        } else failed("HttpArgumentEncodingFailed", ERROR_NOT_ENOUGH_MEMORY);
        ah_free(wide_host); ah_free(wide_path);
        if (request) {
            DWORD policy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
            bool ready = option(WINHTTP_OPTION_AUTOLOGON_POLICY, &policy, sizeof(policy), "HttpAutologonPolicyFailed");
            DWORD disabled = WINHTTP_DISABLE_REDIRECTS;
            if (ah_conservative_probes) ready = ready && option(WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled), "HttpDisableRedirectsFailed");
            if (secure) {

                DWORD certificate_policy = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
                ready = ready && option(WINHTTP_OPTION_SECURITY_FLAGS, &certificate_policy, sizeof(certificate_policy), "HttpTlsPolicyFailed");
            }
            if (!ready) { WINHTTP$WinHttpCloseHandle(request); request = nullptr; }
        }
    }
    ~ah_http_connection() {
        if (request) WINHTTP$WinHttpCloseHandle(request);
        if (connection) WINHTTP$WinHttpCloseHandle(connection);
        if (session) WINHTTP$WinHttpCloseHandle(session);
    }
    ah_http_connection(const ah_http_connection &) = delete;
    ah_http_connection &operator=(const ah_http_connection &) = delete;
    const char *failure_reason() const { return failure[0] ? failure : "HttpRequestFailed"; }
    bool channel_bindings(ah_buffer &storage, SecPkgContext_Bindings *&bindings) {
        bindings = nullptr;
        DWORD size = 0;
        WINHTTP$WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CBT, nullptr, &size);
        if (size < sizeof(SecPkgContext_Bindings) || size > storage.limit) return false;
        storage.data = ah_alloc(size); if (!storage.data) return false;
        storage.capacity = size;
        if (!WINHTTP$WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CBT, storage.data, &size) || size > storage.capacity || size < sizeof(SecPkgContext_Bindings)) return false;
        storage.length = size;
        auto *candidate = reinterpret_cast<SecPkgContext_Bindings *>(storage.data);
        uintptr_t base = reinterpret_cast<uintptr_t>(storage.data), data = reinterpret_cast<uintptr_t>(candidate->Bindings);
        if (data < base + sizeof(*candidate) || data > base + size || candidate->BindingsLength < sizeof(SEC_CHANNEL_BINDINGS) ||
            candidate->BindingsLength > base + size - data) return false;
        bindings = candidate; return true;
    }
    bool exchange(const char *token, DWORD &status, char *authentication, size_t capacity, const char *scheme = "NTLM", bool *epa_misconfigured = nullptr) {
        if (!request) return false;
        failure[0] = 0;
        DWORD response_timeout = 5000;
        if (!option(WINHTTP_OPTION_RECEIVE_TIMEOUT, &response_timeout, sizeof(response_timeout), "HttpReceiveTimeoutOptionFailed")) return false;
        if (token) {
            if (ah_len(token) > 65000 || (!ah_eq(scheme, "NTLM") && !ah_eq(scheme, "Negotiate"))) return failed("HttpInvalidToken", ERROR_INVALID_PARAMETER);
            wchar_t *header = ah_alloc<wchar_t>(65536 * sizeof(wchar_t)); if (!header) return failed("HttpHeaderAllocationFailed", ERROR_NOT_ENOUGH_MEMORY);
            int length = MSVCRT$_snwprintf(header, 65536, L"Authorization: %S %S", scheme, token);
            if (length < 0 || length >= 65536) { ah_free(header); return failed("HttpHeaderTooLarge", ERROR_INSUFFICIENT_BUFFER); }
            bool added = WINHTTP$WinHttpAddRequestHeaders(request, header, static_cast<DWORD>(length), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) != FALSE;
            if (!added) failed("HttpAuthorizationHeaderFailed");
            ah_free(header);
            if (!added) return false;
        }
        if (!WINHTTP$WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) return failed("HttpSendFailed");
        if (!WINHTTP$WinHttpReceiveResponse(request, nullptr)) return failed("HttpReceiveFailed");
        DWORD size = sizeof(status);
        if (!WINHTTP$WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) return failed("HttpStatusQueryFailed");
        if (authentication && capacity) {
            authentication[0] = 0; DWORD index = 0;

            for (unsigned int i = 0; i < 16; ++i) {
                DWORD value_size = 0;
                WINHTTP$WinHttpQueryHeaders(request, WINHTTP_QUERY_WWW_AUTHENTICATE, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &value_size, &index);
                if (!value_size) break;
                if (value_size > 131072 || value_size % sizeof(wchar_t)) return failed("HttpAuthHeaderInvalid", ERROR_INVALID_DATA);
                wchar_t *value = ah_alloc<wchar_t>(value_size + sizeof(wchar_t)); if (!value) return failed("HttpHeaderAllocationFailed", ERROR_NOT_ENOUGH_MEMORY);
                if (!WINHTTP$WinHttpQueryHeaders(request, WINHTTP_QUERY_WWW_AUTHENTICATE, WINHTTP_HEADER_NAME_BY_INDEX, value, &value_size, &index)) { failed("HttpAuthHeaderQueryFailed"); ah_free(value); return false; }
                size_t used = ah_len(authentication);
                if (used && used + 1 < capacity) authentication[used++] = ',';
                bool converted = KERNEL32$WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, authentication + used, static_cast<int>(capacity - used), nullptr, nullptr) != 0;
                if (!converted) failed("HttpAuthHeaderEncodingFailed");
                ah_free(value); if (!converted) return false;
            }
        }

        char body[1024]; DWORD read = 0; size_t total = 0, matched = 0;
        const char marker[] = "ExtendedProtectionPolicy.PolicyEnforcement";
        if (epa_misconfigured) *epa_misconfigured = false;
        const ULONGLONG body_started = KERNEL32$GetTickCount64();
        do {
            ULONGLONG elapsed = KERNEL32$GetTickCount64() - body_started;
            if (elapsed >= 5000) return failed("HttpBodyDeadlineExceeded", ERROR_TIMEOUT);
            DWORD remaining = static_cast<DWORD>(5000 - elapsed);
            if (!option(WINHTTP_OPTION_RECEIVE_TIMEOUT, &remaining, sizeof(remaining), "HttpBodyTimeoutOptionFailed")) return false;
            if (!WINHTTP$WinHttpReadData(request, body, sizeof(body), &read)) return failed("HttpBodyReadFailed");
            if (KERNEL32$GetTickCount64() - body_started >= 5000) return failed("HttpBodyDeadlineExceeded", ERROR_TIMEOUT);
            total += read;
            if (total > 4 * 1024 * 1024) return failed("HttpBodyTooLarge", ERROR_INSUFFICIENT_BUFFER);
            for (DWORD i = 0; i < read; ++i) {
                if (body[i] == marker[matched]) ++matched;
                else matched = body[i] == marker[0] ? 1 : 0;
                if (matched == sizeof(marker) - 1) { if (epa_misconfigured) *epa_misconfigured = true; matched = 0; }
            }
        } while (read);
        return true;
    }
};

static bool ah_extract_auth_challenge(const char *authentication, const char *scheme, char *challenge, size_t capacity) {
    const size_t scheme_size = ah_len(scheme);
    size_t remaining = ah_len(authentication);
    for (const char *p = authentication; *p; ++p, --remaining) {
        if (p != authentication && p[-1] != ',' && p[-1] != ' ') continue;
        if (remaining < scheme_size) continue;
        bool matches = true;
        for (size_t i = 0; i < scheme_size; ++i) if (ah_conservative_probes ? ah_lower(p[i]) != ah_lower(scheme[i]) : p[i] != scheme[i]) { matches = false; break; }
        if (!matches || (p[scheme_size] && p[scheme_size] != ' ' && p[scheme_size] != ',')) continue;
        const char *start = p + scheme_size; while (*start == ' ') ++start;
        size_t i = 0;
        while (start[i] && start[i] != ' ' && start[i] != ',' && start[i] != '\r' && start[i] != '\n') {
            if (i + 1 >= capacity) return false;
            challenge[i] = start[i]; ++i;
        }
        if (!capacity) return false;
        challenge[i] = 0; return true;
    }
    return false;
}

static bool ah_extract_ntlm_challenge(const char *authentication, char *challenge, size_t capacity) {
    return ah_extract_auth_challenge(authentication, "NTLM", challenge, capacity);
}

static bool ah_http_terminal_status(ah_http_probe_result &result, DWORD status, bool epa_misconfigured, unsigned int stage = 0) {
    if (!ah_conservative_probes && stage == 1) return false;
    if (status == 404) {
        if (!ah_conservative_probes) { result.collected = false; result.http_failure_status = status; }
        ah_text_copy(result.status, "NotVulnerable_PathNotFound"); return true;
    }
    if (status == 403) { ah_text_copy(result.status, "NotVulnerable_PathForbidden"); return true; }
    if (status == 500) {
        if (ah_conservative_probes) ah_text_copy(result.status, epa_misconfigured ? "NotVulnerable_EpaMisconfigured" : "NotVulnerable_ServerError");
        else if (!stage) ah_text_copy(result.status, "NotVulnerable_PathNotFound");
        else if (epa_misconfigured) ah_text_copy(result.status, "NotVulnerable_EpaMisconfigured");
        else { result.collected = false; ah_text_copy(result.status, "UnexpectedHttpServerError"); }
        return true;
    }
    return false;
}

static ah_http_probe_result ah_http_probe_attempt(const char *host, uint16_t port, const char *path, bool secure, bool valid_bindings = false) {
    ah_http_probe_result result = {};
    ah_arena arena(1024 * 1024);
    char *authentication = static_cast<char *>(arena.alloc(65536)), *challenge_text = static_cast<char *>(arena.alloc(65024));
    if (!authentication || !challenge_text) { ah_text_copy(result.status, "OutOfMemory"); return result; }
    ah_http_connection http(host, port, path, secure);
    result.collected = true;
    if (secure) ah_text_copy(result.status, "Vulnerable_NtlmHttpsNoChannelBinding"); else ah_text_copy(result.status, "Vulnerable_NtlmHttpEndpoint");
    DWORD status = 0; bool epa_misconfigured = false;
    if (!http.exchange(nullptr, status, authentication, 65536, "NTLM", &epa_misconfigured)) {
        result.collected = false; ah_text_copy(result.status, http.failure_reason());
        if (!ah_conservative_probes && (ah_eq(result.status, "HttpSendFailed:12029") || ah_eq(result.status, "HttpReceiveFailed:12029") ||
            ah_eq(result.status, "HttpSendFailed:12002") || ah_eq(result.status, "HttpReceiveFailed:12002"))) {
            if (ah_host_diagnostics) BeaconPrintf(CALLBACK_OUTPUT, "HTTP %s:%u%s: %s (reference classification=PortInaccessible)", host, static_cast<unsigned int>(port), path, result.status);
            result.collected = true; ah_text_copy(result.status, "NotVulnerable_PortInaccessible");
        }
        return result;
    }
    if (ah_http_terminal_status(result, status, epa_misconfigured)) return result;
    const char *scheme = "NTLM";
    bool advertised = ah_extract_ntlm_challenge(authentication, challenge_text, 65024);
    if (!advertised) { scheme = "Negotiate"; advertised = ah_extract_auth_challenge(authentication, scheme, challenge_text, 65024); }
    if (!ah_conservative_probes && advertised) {
        auto scheme_at = [](const char *text, const char *name) {
            size_t i = 0; for (; name[i]; ++i) if (text[i] != name[i]) return false;
            return !text[i] || text[i] == ' ' || text[i] == ',';
        };
        for (const char *p = authentication; *p; ++p) {
            if (p != authentication && p[-1] != ',' && p[-1] != ' ') continue;
            if (scheme_at(p, "Negotiate")) { scheme = "Negotiate"; break; }
            if (scheme_at(p, "NTLM")) { scheme = "NTLM"; break; }
        }
    }
    bool successful_non_ok = !ah_conservative_probes && status > 200 && status < 300;
    if ((status != 401 && !successful_non_ok) || !advertised) {
        if (!ah_conservative_probes) {
            if (status == 200) { result.collected = false; ah_text_copy(result.status, "AuthenticationNotRequired"); }
            else if (status == 401 || (status >= 200 && status < 300)) result.vulnerable = true;
            else { result.collected = false; ah_text_copy(result.status, "UnexpectedHttpStatus"); }
            return result;
        }
        if (status != 401 && (status < 200 || status >= 300)) { result.collected = false; ah_text_copy(result.status, "UnexpectedHttpStatus"); return result; }
        ah_text_copy(result.status, "NotVulnerable_NoNtlmChallenge");
        return result;
    }
    struct context_guard { ah_ntlm_context value = {}; ~context_guard() { ah_ntlm_free(value); } } guard;
    ah_ntlm_context &context = guard.value;
    char *target = ah_concat(arena, "HTTP/", host);
    char *first = ah_ntlm_token(context, target, nullptr, 0);
    if (!first) { result.collected = false; ah_text_copy(result.status, "NtlmNegotiateFailed"); return result; }
    status = 0; authentication[0] = 0;
    if (!http.exchange(first, status, authentication, 65536, scheme, &epa_misconfigured)) {
        ah_free(first); result.collected = false; ah_text_copy(result.status, http.failure_reason()); return result;
    }
    ah_free(first);
    if (ah_http_terminal_status(result, status, epa_misconfigured, 1)) return result;
    challenge_text[0] = 0;
    if ((ah_conservative_probes && status != 401) || !ah_extract_auth_challenge(authentication, scheme, challenge_text, 65024) || !*challenge_text) {
        if (!ah_conservative_probes && ah_extract_auth_challenge(authentication, scheme, challenge_text, 65024) && !*challenge_text) {
            ah_text_copy(result.status, "NotVulnerable_NoNtlmChallenge"); return result;
        }
        result.collected = false; ah_text_copy(result.status, "NtlmHandshakeIncomplete"); return result;
    }
    size_t challenge_size = 0;
    unsigned char *challenge = ah_base64_decode(challenge_text, &challenge_size);
    if (!challenge || challenge_size < 48 || ah_u32(challenge) != 0x4d4c544eU || ah_u32(challenge + 4) != 0x00505353U || ah_u32(challenge + 8) != 2) {
        ah_free(challenge); result.collected = false; ah_text_copy(result.status, "InvalidNtlmChallenge"); return result;
    }
    ah_buffer binding_storage(65536); SecPkgContext_Bindings *bindings = nullptr;
    if (valid_bindings && !http.channel_bindings(binding_storage, bindings)) {
        ah_free(challenge); result.collected = false; ah_text_copy(result.status, "TlsChannelBindingsUnavailable"); return result;
    }
    char *second = ah_ntlm_token(context, target, challenge, challenge_size, bindings ? bindings->Bindings : nullptr, bindings ? bindings->BindingsLength : 0);
    ah_free(challenge);
    if (!second) { result.collected = false; ah_text_copy(result.status, "NtlmAuthenticateFailed"); return result; }
    status = 0; authentication[0] = 0;
    if (!http.exchange(second, status, authentication, 65536, scheme, &epa_misconfigured)) {
        ah_free(second); result.collected = false; ah_text_copy(result.status, http.failure_reason()); return result;
    }
    ah_free(second);
    if (ah_http_terminal_status(result, status, epa_misconfigured, 2)) return result;
    if (status >= 200 && status < 300) result.vulnerable = true;
    else if (status == 401) {
        if (secure && !ah_conservative_probes) { result.epa = true; ah_text_copy(result.status, "NotVulnerable_NtlmChannelBindingRequired"); }
        else { ah_text_copy(result.status, "NtlmAuthenticationRejected"); result.collected = false; }
    }
    else { result.collected = false; ah_text_copy(result.status, "UnexpectedHttpStatus"); }
    return result;
}

static ah_http_probe_result ah_http_probe(const char *host, uint16_t port, const char *path, bool secure) {
    ah_http_probe_result result = ah_http_probe_attempt(host, port, path, secure);

    if (secure && !result.collected && ah_eq(result.status, "NtlmAuthenticationRejected")) {
        ah_http_probe_result control = ah_http_probe_attempt(host, port, path, true, true);
        if (control.collected && control.vulnerable) {
            result.collected = true; result.epa = true; result.vulnerable = false;
            ah_text_copy(result.status, "NotVulnerable_NtlmChannelBindingRequired");
        }
    }
    return result;
}

class ah_winsock final {
    bool ready = false;
public:
    ah_winsock() { WSADATA data = {}; ready = WS2_32$WSAStartup(MAKEWORD(2, 2), &data) == 0; }
    ~ah_winsock() { if (ready) WS2_32$WSACleanup(); }
    bool valid() const { return ready; }
    ah_winsock(const ah_winsock &) = delete;
    ah_winsock &operator=(const ah_winsock &) = delete;
};

static SOCKET ah_tcp_connect(const char *host, uint16_t port, DWORD timeout_ms = 5000) {
    if (!host || !*host || !timeout_ms) return INVALID_SOCKET;
    const ULONGLONG started = KERNEL32$GetTickCount64();
    addrinfo hints = {}, *addresses = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP; hints.ai_flags = AI_NUMERICSERV;
    char digits[16]; const char *service = ah_decimal(digits + sizeof(digits), port);
    if (WS2_32$getaddrinfo(host, service, &hints, &addresses) != 0 || !addresses) return INVALID_SOCKET;
    struct address_guard { addrinfo *value; ~address_guard() { WS2_32$freeaddrinfo(value); } } guard{addresses};
    auto usable = [](const addrinfo *address) {
        return address->ai_addr && ((address->ai_family == AF_INET && address->ai_addrlen >= sizeof(sockaddr_in)) ||
               (address->ai_family == AF_INET6 && address->ai_addrlen >= sizeof(sockaddr_in6))) &&
               address->ai_addrlen <= sizeof(sockaddr_storage) && address->ai_addr->sa_family == address->ai_family;
    };
    size_t candidates = 0;
    for (addrinfo *address = addresses; address; address = address->ai_next) if (usable(address)) ++candidates;
    for (addrinfo *address = addresses; address; address = address->ai_next) {
        if (!usable(address)) continue;
        ULONGLONG elapsed = KERNEL32$GetTickCount64() - started;
        if (elapsed >= timeout_ms) break;

        DWORD attempt_ms = static_cast<DWORD>((timeout_ms - elapsed) / candidates--);
        if (!attempt_ms) attempt_ms = 1;
        SOCKET socket = WS2_32$socket(address->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (socket == INVALID_SOCKET) continue;
        u_long nonblocking = 1;
        if (WS2_32$ioctlsocket(socket, FIONBIO, &nonblocking) != 0) { WS2_32$closesocket(socket); continue; }
        bool connected = WS2_32$connect(socket, address->ai_addr, static_cast<int>(address->ai_addrlen)) == 0;
        if (!connected && WS2_32$WSAGetLastError() == WSAEWOULDBLOCK) {
            elapsed = KERNEL32$GetTickCount64() - started;
            if (elapsed >= timeout_ms) { WS2_32$closesocket(socket); break; }
            if (attempt_ms > timeout_ms - elapsed) attempt_ms = static_cast<DWORD>(timeout_ms - elapsed);
            fd_set write_set, error_set; FD_ZERO(&write_set); FD_SET(socket, &write_set); FD_ZERO(&error_set); FD_SET(socket, &error_set);
            timeval timeout = {static_cast<long>(attempt_ms / 1000), static_cast<long>((attempt_ms % 1000) * 1000)};
            connected = WS2_32$select(0, nullptr, &write_set, &error_set, &timeout) > 0 && write_set.fd_count == 1 && write_set.fd_array[0] == socket;
        }
        int error = 0, size = sizeof(error);
        connected = connected && WS2_32$getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &size) == 0 && error == 0;
        nonblocking = 0;
        if (!connected || KERNEL32$GetTickCount64() - started >= timeout_ms || WS2_32$ioctlsocket(socket, FIONBIO, &nonblocking) != 0 ||
            WS2_32$setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout_ms), sizeof(timeout_ms)) != 0 ||
            WS2_32$setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeout_ms), sizeof(timeout_ms)) != 0) {
            WS2_32$closesocket(socket); continue;
        }
        return socket;
    }
    return INVALID_SOCKET;
}

static bool ah_tcp_open(const char *host, uint16_t port) {
    ah_winsock wsa; if (!wsa.valid()) return false;
    SOCKET socket = ah_tcp_connect(host, port);
    if (socket == INVALID_SOCKET) return false;
    WS2_32$closesocket(socket); return true;
}

static bool ah_tcp_open_timeout(const char *host, uint16_t port, int timeout_ms) {
    if (timeout_ms <= 0) return false;
    ah_winsock wsa; if (!wsa.valid()) return false;
    SOCKET socket = ah_tcp_connect(host, port, static_cast<DWORD>(timeout_ms));
    if (socket == INVALID_SOCKET) return false;
    WS2_32$closesocket(socket); return true;
}

static const char *ah_ldap_failure(ah_arena &arena, const char *stage, ULONG status) {
    char digits[32]; const char *number = ah_decimal(digits + sizeof(digits), status);
    return ah_concat(arena, stage, number);
}

static bool ah_ldap_server_status(LDAP *ld, const char *expected) {
    wchar_t *diagnostic = nullptr;
    if (WLDAP32$ldap_get_optionW(ld, LDAP_OPT_SERVER_ERROR, &diagnostic) != LDAP_SUCCESS || !diagnostic) return false;
    bool match = true; size_t length = ah_wlen(diagnostic), expected_length = ah_len(expected);
    if (length < expected_length) match = false;
    else for (size_t i = 0; i < expected_length; ++i) {
        wchar_t actual = diagnostic[i];
        if (actual >= L'A' && actual <= L'Z') actual += L'a' - L'A';
        if (actual != static_cast<wchar_t>(ah_lower(expected[i]))) { match = false; break; }
    }
    WLDAP32$ldap_memfreeW(diagnostic);
    return match;
}

static LDAP *ah_ldap_probe_open(const char *host, bool secure, ah_arena &arena, const char *&failure) {
    wchar_t *wide_host = ah_wide(host);
    if (!wide_host) { failure = "LdapHostEncodingFailed"; return nullptr; }
    LDAP *ld = WLDAP32$ldap_sslinitW(wide_host, secure ? 636 : 389, secure ? 1 : 0);
    ah_free(wide_host);
    if (!ld) { failure = "LdapInitializationFailed"; return nullptr; }
    ULONG version = LDAP_VERSION3, off = 0, timeout_seconds = 5;
    ULONG result = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result == LDAP_SUCCESS) result = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_REFERRALS, &off);
    if (result == LDAP_SUCCESS) result = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_AUTO_RECONNECT, &off);
    if (result == LDAP_SUCCESS) result = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_TIMELIMIT, &timeout_seconds);
    if (result == LDAP_SUCCESS) result = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_SIGN, &off);
    if (result == LDAP_SUCCESS) result = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_ENCRYPT, &off);
    if (result == LDAP_SUCCESS && secure) result = WLDAP32$ldap_set_optionW(ld, LDAP_OPT_SERVER_CERTIFICATE, reinterpret_cast<void *>(ah_ldap_accept_certificate));
    if (result != LDAP_SUCCESS) { failure = ah_ldap_failure(arena, "LdapOptionFailed:", result); WLDAP32$ldap_unbind(ld); return nullptr; }
    struct l_timeval timeout = {5, 0};
    result = WLDAP32$ldap_connect(ld, &timeout);
    if (result != LDAP_SUCCESS) { failure = ah_ldap_failure(arena, "LdapConnectFailed:", result); WLDAP32$ldap_unbind(ld); return nullptr; }
    return ld;
}

static int ah_ldap_signing_attempt(const char *host, ah_arena &arena, const char *&failure) {
    LDAP *ld = ah_ldap_probe_open(host, false, arena, failure);
    if (!ld) return -1;
    ULONG result = WLDAP32$ldap_bind_sW(ld, nullptr, nullptr, LDAP_AUTH_NTLM);
    if (result != LDAP_STRONG_AUTH_REQUIRED && result != LDAP_SUCCESS) failure = ah_ldap_server_status(ld, "80090302") ? "NtlmNotSupported" : ah_ldap_failure(arena, "LdapNtlmBindFailed:", result);
    WLDAP32$ldap_unbind(ld);
    if (result == LDAP_STRONG_AUTH_REQUIRED) return 1;
    if (result == LDAP_SUCCESS) return 0;
    return -1;
}

static const char *ah_ldap_challenge_failure(ah_arena &arena, ULONG api_result, ULONG option_result, ULONG server_result, const BERVAL *challenge) {
    auto append_number = [&](const char *prefix, ULONG number) {
        char digits[32]; return ah_concat(arena, prefix, ah_decimal(digits + sizeof(digits), number));
    };
    const char *reason = append_number("LdapsNtlmChallengeFailed:api=", api_result);
    reason = append_number(ah_concat(arena, reason, ",option="), option_result);
    reason = append_number(ah_concat(arena, reason, ",result="), server_result);
    reason = append_number(ah_concat(arena, reason, ",response="), challenge ? 1UL : 0UL);
    reason = append_number(ah_concat(arena, reason, ",data="), challenge && challenge->bv_val ? 1UL : 0UL);
    return append_number(ah_concat(arena, reason, ",length="), challenge ? challenge->bv_len : 0UL);
}

static int ah_ldaps_bad_bindings_attempt(const char *host, ah_arena &arena, const char *&failure) {
    LDAP *ld = ah_ldap_probe_open(host, true, arena, failure);
    if (!ld) return -1;
    struct ldap_guard { LDAP *value; ~ldap_guard() { WLDAP32$ldap_unbind(value); } } connection{ld};
    struct context_guard { ah_ntlm_context value = {}; ~context_guard() { ah_ntlm_free(value); } } context;
    const char *spn = ah_concat(arena, "LDAP/", host);
    size_t token_size = 0;
    unsigned char *token = ah_ntlm_step(context.value, spn, nullptr, 0, token_size);
    if (!token) { failure = "NtlmNegotiateFailed"; return -1; }
    BERVAL credential = {static_cast<ULONG>(token_size), reinterpret_cast<char *>(token)}; BERVAL *challenge = nullptr;

    ULONG result = WLDAP32$ldap_sasl_bind_sW(ld, const_cast<wchar_t *>(L""), const_cast<wchar_t *>(L"GSS-SPNEGO"), &credential, nullptr, nullptr, &challenge);
    ULONG server_result = LDAP_OTHER;
    ULONG option_result = WLDAP32$ldap_get_optionW(ld, LDAP_OPT_ERROR_NUMBER, &server_result);
    ah_free(token);

    if ((result != LDAP_SUCCESS && result != LDAP_SASL_BIND_IN_PROGRESS) || option_result != LDAP_SUCCESS ||
        (server_result != LDAP_SUCCESS && server_result != LDAP_SASL_BIND_IN_PROGRESS) ||
        !challenge || !challenge->bv_val || challenge->bv_len < 48 || challenge->bv_len > 65536) {
        failure = ah_ldap_server_status(ld, "80090302") ? "NtlmNotSupported" : ah_ldap_challenge_failure(arena, result, option_result, server_result, challenge);
        if (challenge) WLDAP32$ber_bvfree(challenge);
        return -1;
    }
    const unsigned char *raw = reinterpret_cast<const unsigned char *>(challenge->bv_val);
    if (ah_u32(raw) != 0x4d4c544eU || ah_u32(raw + 4) != 0x00505353U || ah_u32(raw + 8) != 2) {
        failure = ah_concat(arena, "InvalidNtlmChallenge:", ah_ldap_challenge_failure(arena, result, option_result, server_result, challenge));
        WLDAP32$ber_bvfree(challenge); return -1;
    }
    token = ah_ntlm_step(context.value, spn, raw, challenge->bv_len, token_size, true);
    WLDAP32$ber_bvfree(challenge);
    if (!token) { failure = "NtlmAuthenticateFailed"; return -1; }
    credential = {static_cast<ULONG>(token_size), reinterpret_cast<char *>(token)}; BERVAL *response = nullptr;
    result = WLDAP32$ldap_sasl_bind_sW(ld, const_cast<wchar_t *>(L""), const_cast<wchar_t *>(L"GSS-SPNEGO"), &credential, nullptr, nullptr, &response);
    server_result = LDAP_OTHER;
    option_result = WLDAP32$ldap_get_optionW(ld, LDAP_OPT_ERROR_NUMBER, &server_result);
    ah_free(token); if (response) WLDAP32$ber_bvfree(response);
    if (result == LDAP_SUCCESS || result == LDAP_SASL_BIND_IN_PROGRESS) {
        if (option_result != LDAP_SUCCESS) { failure = ah_ldap_failure(arena, "LdapsBindResultOptionFailed:", option_result); return -1; }
        result = server_result;
    }
    if (result == LDAP_SUCCESS) return 1;
    if (result == LDAP_INVALID_CREDENTIALS && ah_ldap_server_status(ld, "80090346")) return 0;
    failure = ah_ldap_server_status(ld, "80090302") ? "NtlmNotSupported" : ah_ldap_failure(arena, "LdapsNtlmBindFailed:", result);
    return -1;
}

static int ah_ldap_signing(const char *host, ah_arena &arena, const char *&failure) {
    int result = ah_ldap_signing_attempt(host, arena, failure);
    if (result < 0 && !ah_conservative_probes) {
        if (ah_host_diagnostics) BeaconPrintf(CALLBACK_OUTPUT, "LDAP signing %s: %s (reference classification=true)", host, failure ? failure : "AuthenticationFailed");
        return 1;
    }
    return result;
}
static int ah_ldaps_bad_bindings(const char *host, ah_arena &arena, const char *&failure) {
    int result = ah_ldaps_bad_bindings_attempt(host, arena, failure);
    if (result < 0 && !ah_conservative_probes) {
        if (ah_host_diagnostics) BeaconPrintf(CALLBACK_OUTPUT, "LDAPS CBT %s: %s (reference classification=false)", host, failure ? failure : "AuthenticationFailed");
        return 0;
    }
    return result;
}

static bool ah_smb_signing_response(const unsigned char *response, size_t size, bool &required) {
    if (size < 40 || response[0] != 0) return false;
    uint32_t frame_size = (static_cast<uint32_t>(response[1]) << 16) | (static_cast<uint32_t>(response[2]) << 8) | response[3];
    if (ah_u32(response + 4) == 0x424d53ffU) {

        if (frame_size < 69 || response[8] != 0x72 || ah_u32(response + 9) != 0 ||
            !(response[13] & 0x80) || response[36] != 17 || ah_u16(response + 37) != 0) return false;
        required = (response[39] & 0x0c) == 0x0c;
        return true;
    }
    if (size < 72) return false;
    if (frame_size < 128 || ah_u32(response + 4) != 0x424d53feU || ah_u16(response + 8) != 64 ||
        ah_u32(response + 12) != 0 || ah_u16(response + 16) != 0 || !(ah_u32(response + 20) & 1) || ah_u16(response + 68) != 65) return false;
    required = (ah_u16(response + 70) & 3) == 3;
    return true;
}

static void ah_smb_u16(unsigned char *p, uint16_t value) { p[0] = static_cast<unsigned char>(value); p[1] = static_cast<unsigned char>(value >> 8); }
static void ah_smb_u32(unsigned char *p, uint32_t value) { for (size_t i = 0; i < 4; ++i) p[i] = static_cast<unsigned char>(value >> (i * 8)); }

static bool ah_smb_negotiate_request(ah_buffer &packet, bool smb1) {
    if (smb1) {
        unsigned char request[73] = {};
        request[3] = sizeof(request) - 4;
        request[4] = 0xff; request[5] = 'S'; request[6] = 'M'; request[7] = 'B'; request[8] = 0x72;
        request[13] = 0x18; ah_smb_u16(request + 14, 0xc853); ah_smb_u16(request + 28, 0xffff); ah_smb_u16(request + 30, 0xfeff);
        ah_smb_u16(request + 37, 34);
        const char dialects[] = "\x02NT LM 0.12\0\x02SMB 2.002\0\x02SMB 2.???\0";
        for (size_t i = 0; i < 34; ++i) request[39 + i] = static_cast<unsigned char>(dialects[i]);
        ah_append(&packet, reinterpret_cast<const char *>(request), sizeof(request));
        return !packet.failed;
    }

    unsigned char request[204] = {};
    request[3] = sizeof(request) - 4;
    request[4] = 0xfe; request[5] = 'S'; request[6] = 'M'; request[7] = 'B'; request[8] = 64; request[18] = 1;
    ah_smb_u16(request + 68, 36); ah_smb_u16(request + 70, 5); ah_smb_u16(request + 72, 1);
    ah_smb_u32(request + 76, 0x40);
    ah_native_library bcrypt(L"bcrypt.dll");
    using generate_random = LONG (WINAPI *)(void *, unsigned char *, ULONG, ULONG);
    auto random = bcrypt.find<generate_random>("BCryptGenRandom");
    if (!random || random(nullptr, request + 80, 16, 2) < 0 || random(nullptr, request + 130, 32, 2) < 0) return false;
    request[87] = static_cast<unsigned char>((request[87] & 0x0f) | 0x40); request[88] = static_cast<unsigned char>((request[88] & 0x3f) | 0x80);
    ah_smb_u32(request + 96, 112); ah_smb_u16(request + 100, 3);
    const uint16_t dialects[] = {0x0202, 0x0210, 0x0300, 0x0302, 0x0311};
    for (size_t i = 0; i < sizeof(dialects) / sizeof(dialects[0]); ++i) ah_smb_u16(request + 104 + i * 2, dialects[i]);

    ah_smb_u16(request + 116, 1); ah_smb_u16(request + 118, 38);
    ah_smb_u16(request + 124, 1); ah_smb_u16(request + 126, 32); ah_smb_u16(request + 128, 1);

    ah_smb_u16(request + 164, 2); ah_smb_u16(request + 166, 10); ah_smb_u16(request + 172, 4);
    const uint16_t ciphers[] = {2, 1, 4, 3};
    for (size_t i = 0; i < sizeof(ciphers) / sizeof(ciphers[0]); ++i) ah_smb_u16(request + 174 + i * 2, ciphers[i]);

    ah_smb_u16(request + 188, 8); ah_smb_u16(request + 190, 8); ah_smb_u16(request + 196, 3);
    ah_smb_u16(request + 198, 2); ah_smb_u16(request + 200, 1); ah_smb_u16(request + 202, 0);
    ah_append(&packet, reinterpret_cast<const char *>(request), sizeof(request));
    return !packet.failed;
}

static bool ah_smb_transfer(SOCKET socket, unsigned char *data, size_t size, bool send, ULONGLONG deadline) {
    size_t transferred = 0;
    while (transferred < size) {
        ULONGLONG now = KERNEL32$GetTickCount64(); if (now >= deadline) return false;
        DWORD timeout = static_cast<DWORD>(deadline - now);
        if (WS2_32$setsockopt(socket, SOL_SOCKET, send ? SO_SNDTIMEO : SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout)) != 0) return false;
        int count = send ? WS2_32$send(socket, reinterpret_cast<const char *>(data + transferred), static_cast<int>(size - transferred), 0) :
                           WS2_32$recv(socket, reinterpret_cast<char *>(data + transferred), static_cast<int>(size - transferred), 0);
        if (count <= 0) return false;
        transferred += static_cast<size_t>(count);
    }
    return true;
}

static bool ah_smb_signing_attempt(const char *host, bool smb1, bool &required) {
    ah_buffer request(1024); if (!ah_smb_negotiate_request(request, smb1)) return false;
    SOCKET socket = ah_tcp_connect(host, 445); if (socket == INVALID_SOCKET) return false;
    struct socket_guard { SOCKET value; ~socket_guard() { WS2_32$closesocket(value); } } guard{socket};
    ULONGLONG deadline = KERNEL32$GetTickCount64() + 5000;
    if (!ah_smb_transfer(socket, reinterpret_cast<unsigned char *>(request.data), request.length, true, deadline)) return false;
    unsigned char header[4] = {};
    if (!ah_smb_transfer(socket, header, sizeof(header), false, deadline) || header[0] != 0) return false;
    uint32_t size = (static_cast<uint32_t>(header[1]) << 16) | (static_cast<uint32_t>(header[2]) << 8) | header[3];
    if (size < 36 || size > 1024 * 1024) return false;
    ah_buffer response(1024 * 1024 + 4);
    response.data = ah_alloc(size + 4); if (!response.data) return false;
    response.length = response.capacity = size + 4;
    for (size_t i = 0; i < 4; ++i) response.data[i] = static_cast<char>(header[i]);
    if (!ah_smb_transfer(socket, reinterpret_cast<unsigned char *>(response.data) + 4, size, false, deadline)) return false;
    return ah_smb_signing_response(reinterpret_cast<unsigned char *>(response.data), response.length, required);
}

static bool ah_smb_local_signing(const char *host, bool &required) {

    ah_native_library kernel(L"kernel32.dll");
    auto computer_name = kernel.find<decltype(&GetComputerNameExW)>("GetComputerNameExW");
    if (!computer_name) return false;
    ah_arena names(65536 + 1024); bool local = false;
    wchar_t value[256]; DWORD size = sizeof(value) / sizeof(value[0]);
    if (computer_name(ComputerNameDnsFullyQualified, value, &size)) local = ah_eq(names.utf8(value), host);
    if (!local) {
        size = sizeof(value) / sizeof(value[0]);
        if (computer_name(ComputerNameNetBIOS, value, &size)) local = ah_eq(names.utf8(value), host);
    }
    if (!local) return false;
    HKEY key = nullptr;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters", 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return false;
    auto dword = [&](const wchar_t *name, DWORD &out) {
        DWORD type = 0, bytes = sizeof(out);
        return ADVAPI32$RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE *>(&out), &bytes) == ERROR_SUCCESS && type == REG_DWORD && bytes == sizeof(out);
    };
    DWORD value_required = 0, value_enabled = 0;
    bool has_required = dword(L"RequireSecuritySignature", value_required), has_enabled = dword(L"EnableSecuritySignature", value_enabled);
    ADVAPI32$RegCloseKey(key);
    if (has_required) { required = value_required != 0; return true; }
    if (has_enabled && !value_enabled) { required = false; return true; }
    return false;
}

static bool ah_smb_signing(const char *host, bool &collected) {
    collected = false;
    bool required = false;
    if (ah_smb_local_signing(host, required)) { collected = true; return required; }
    ah_winsock wsa; if (!wsa.valid()) return false;

    collected = ah_smb_signing_attempt(host, true, required) || ah_smb_signing_attempt(host, false, required);
    return required;
}

static void ah_collect_service_probes(ah_graph &g, ah_object *o) {
    const char *host = ah_api_hostname(g, o);
    if (!*host) return;
    if (ah_collection & AH_SMBINFO) {
        o->smb_signing = ah_smb_signing(host, o->smb_signing_collected);
    }
    if ((ah_collection & AH_LDAP_SERVICES) && (ah_integer(o, "userAccountControl") & 0x2000)) {
        o->ldap_available = ah_tcp_open(host, 389);
        o->ldaps_available = ah_tcp_open(host, 636);
        if (o->ldap_available) {
            int signing = ah_ldap_signing(host, g.directory.arena, o->ldap_signing_failure);
            if (signing >= 0) { o->ldap_signing_valid = true; o->ldap_signing = signing != 0; }
        } else if (ah_conservative_probes) o->ldap_signing_failure = "LdapPortInaccessible";
        if (o->ldaps_available) {
            int disabled = ah_ldaps_bad_bindings(host, g.directory.arena, o->ldaps_cbt_failure);
            if (disabled >= 0) { o->ldaps_cbt_valid = true; o->ldaps_cbt_disabled = disabled != 0; }
        } else if (ah_conservative_probes) o->ldaps_cbt_failure = "LdapsPortInaccessible";
    }
}
