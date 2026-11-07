#pragma once
#include "sha1.hpp"

struct ah_flag_name { uint32_t flag; const char *name; };
static void ah_adcs_binary_array(ah_buffer &b, ah_value *values) {
    AH_TEXT(&b, "["); bool first = true;
    for (ah_value *v = values; v; v = v->next) {
        char *encoded = ah_base64_encode(reinterpret_cast<const unsigned char *>(v->data), v->size);
        if (!encoded) { b.failed = true; return; }
        if (!first) { AH_TEXT(&b, ","); } first = false;
        ah_string(b, encoded); ah_free(encoded);
    }
    AH_TEXT(&b, "]");
}
static char *ah_flag_names(ah_arena &arena, uint64_t flags, const ah_flag_name *names, size_t count) {
    ah_buffer out(1024); bool first = true;
    for (size_t i = 0; i < count; ++i) if (flags & names[i].flag) {
        if (!first) { AH_TEXT(&out, ", "); }
        first = false; ah_append(&out, names[i].name, ah_len(names[i].name));
    }
    AH_TEXT(&out, "\0");
    return out.failed ? nullptr : arena.copy(out.data);
}

static char *ah_adcs_ca_flags(ah_arena &arena, const ah_object *o) {
    static const ah_flag_name names[] = {{1, "NO_TEMPLATE_SUPPORT"}, {2, "SUPPORTS_NT_AUTHENTICATION"},
        {4, "CA_SUPPORTS_MANUAL_AUTHENTICATION"}, {8, "CA_SERVERTYPE_ADVANCED"}};
    return ah_flag_names(arena, static_cast<uint32_t>(ah_integer(o, "flags")), names, sizeof(names) / sizeof(names[0]));
}

static void ah_adcs_enum_property(ah_buffer &b, ah_fields &props, const char *name, const ah_object *o,
                                  const char *attribute, uint32_t known_bits, const char *zero_name,
                                  const char *formatted, bool signed_enum = false) {
    if (!o->values(attribute)) return;
    uint32_t value = static_cast<uint32_t>(ah_integer(o, attribute));
    if (value & ~known_bits || (!value && !zero_name)) {
        props.number(name, signed_enum ? static_cast<int64_t>(static_cast<int32_t>(value)) : static_cast<int64_t>(value));
    } else {
        props.key(name); ah_string(b, value ? formatted : zero_name);
    }
}

static char *ah_adcs_enrollment_flags(ah_arena &arena, const ah_object *o) {
    static const ah_flag_name names[] = {
        {0x00000001, "INCLUDE_SYMMETRIC_ALGORITHMS"}, {0x00000002, "PEND_ALL_REQUESTS"},
        {0x00000004, "PUBLISH_TO_KRA_CONTAINER"}, {0x00000008, "PUBLISH_TO_DS"},
        {0x00000010, "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE"}, {0x00000020, "AUTO_ENROLLMENT"},
        {0x00000040, "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT"}, {0x00000080, "CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED"},
        {0x00000100, "USER_INTERACTION_REQUIRED"}, {0x00000200, "ADD_TEMPLATE_NAME"},
        {0x00000400, "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE"}, {0x00000800, "ALLOW_ENROLL_ON_BEHALF_OF"},
        {0x00001000, "ADD_OCSP_NOCHECK"}, {0x00002000, "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL"},
        {0x00004000, "NOREVOCATIONINFOINISSUEDCERTS"}, {0x00008000, "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS"},
        {0x00010000, "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT"},
        {0x00020000, "ISSUANCE_POLICIES_FROM_REQUEST"}, {0x00040000, "SKIP_AUTO_RENEWAL"}, {0x00080000, "NO_SECURITY_EXTENSION"}
    };
    return ah_flag_names(arena, static_cast<uint32_t>(ah_integer(o, "msPKI-Enrollment-Flag")), names, sizeof(names) / sizeof(names[0]));
}

static char *ah_adcs_name_flags(ah_arena &arena, const ah_object *o) {
    static const ah_flag_name names[] = {
        {0x00000001, "ENROLLEE_SUPPLIES_SUBJECT"}, {0x00000002, "ADD_EMAIL"},
        {0x00000004, "ADD_OBJ_GUID"}, {0x00000008, "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME"},
        {0x00000100, "ADD_DIRECTORY_PATH"}, {0x00010000, "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"},
        {0x00400000, "SUBJECT_ALT_REQUIRE_DOMAIN_DNS"}, {0x00800000, "SUBJECT_ALT_REQUIRE_SPN"},
        {0x01000000, "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID"}, {0x02000000, "SUBJECT_ALT_REQUIRE_UPN"},
        {0x04000000, "SUBJECT_ALT_REQUIRE_EMAIL"}, {0x08000000, "SUBJECT_ALT_REQUIRE_DNS"},
        {0x10000000, "SUBJECT_REQUIRE_DNS_AS_CN"}, {0x20000000, "SUBJECT_REQUIRE_EMAIL"},
        {0x40000000, "SUBJECT_REQUIRE_COMMON_NAME"}, {0x80000000, "SUBJECT_REQUIRE_DIRECTORY_PATH"}
    };
    return ah_flag_names(arena, static_cast<uint32_t>(ah_integer(o, "msPKI-Certificate-Name-Flag")), names, sizeof(names) / sizeof(names[0]));
}

static void ah_adcs_application_policies(ah_buffer &b, const ah_object *o, uint32_t schema, bool legacy) {
    ah_value *values = o->values("msPKI-RA-Application-Policies");
    if (schema == 1 || schema == 2 || (schema == 4 && legacy)) { ah_text_array(b, values); return; }
    AH_TEXT(&b, "["); bool first = true;
    if (values) {
        const char *data = values->data;
        for (size_t index = 0; data[index];) {
            const char *parts[3] = {nullptr, nullptr, nullptr};
            size_t lengths[3] = {0, 0, 0};
            bool complete = true;
            for (unsigned int part = 0; part < 3; ++part) {
                parts[part] = data + index;
                while (data[index] && data[index] != '`') { ++index; ++lengths[part]; }
                if (part < 2 && data[index] != '`') { complete = false; break; }
                if (data[index] == '`') ++index;
            }
            if (complete && lengths[0] == ah_len("mspki-ra-application-policies") && ah_prefix(parts[0], "mspki-ra-application-policies")) {
                if (!first) { AH_TEXT(&b, ","); }
                first = false; ah_json_bytes(&b, parts[2], lengths[2]);
            }
            if (!data[index]) break;
        }
    }
    AH_TEXT(&b, "]");
}

static void ah_adcs_cert_properties(ah_graph &g, ah_buffer &b, ah_fields &props, ah_object *o) {
    ah_value *certificate = o->values("cACertificate");
    if (!certificate || !certificate->size) return;
    char *thumbprint = ah_thumbprint(g.arena, o->values("cACertificate"));
    props.text("certthumbprint", thumbprint); props.text("certname", thumbprint);
    props.key("certchain"); ah_certificate_chain(g, b, o);
    bool path_constraint = false; uint32_t path_length = 0;
    if (certificate) {
        PCCERT_CONTEXT context = CRYPT32$CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, reinterpret_cast<const BYTE *>(certificate->data), static_cast<DWORD>(certificate->size));
        if (context) {
            PCERT_EXTENSION extension = CRYPT32$CertFindExtension(szOID_BASIC_CONSTRAINTS2, context->pCertInfo->cExtension, context->pCertInfo->rgExtension);
            CERT_BASIC_CONSTRAINTS2_INFO info = {}; DWORD size = sizeof(info);
            if (extension && CRYPT32$CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, extension->Value.pbData, extension->Value.cbData, 0, &info, &size)) {
                path_constraint = info.fPathLenConstraint != 0;
                if (path_constraint) path_length = info.dwPathLenConstraint;
            }
            CRYPT32$CertFreeCertificateContext(context);
        }
    }
    props.boolean("hasbasicconstraints", path_constraint); props.number("basicconstraintpathlength", path_length);
}

static void ah_adcs_endpoint(ah_buffer &b, const char *host, uint16_t port, const char *path, const char *url, const char *type, bool secure) {
    ah_http_probe_result probe = ah_http_probe(host, port, path, secure);
    if (!probe.collected) {
        if (probe.http_failure_status == 404) {

            ah_buffer failure(0,4096);
            AH_TEXT(&failure,"HttpRequestException occurred checking NTLM accessibility for URL: ");
            ah_append(&failure,url,ah_len(url));
            AH_TEXT(&failure,". Exception: Response status code does not indicate success: 404 (Not Found).\0");
            if(failure.failed){b.failed=true;return;}
            AH_TEXT(&b,"{\"Result\":null,\"Collected\":false,\"FailureReason\":");
            ah_string(b,failure.data);AH_TEXT(&b,"}");return;
        }
        AH_TEXT(&b, "{\"Result\":null,\"Collected\":false,\"FailureReason\":"); ah_string(b, probe.status); AH_TEXT(&b, "}"); return;
    }
    AH_TEXT(&b, "{\"Result\":{"); ah_fields result(b);
    result.text("Url", url); result.text("Type", type); result.text("Status", probe.status);
    result.boolean("ADCSWebEnrollmentHTTP", !secure && probe.vulnerable);
    result.boolean("ADCSWebEnrollmentHTTPS", secure && (probe.vulnerable || probe.epa));
    result.boolean("ADCSWebEnrollmentEPA", probe.epa);
    AH_TEXT(&b, "},\"Collected\":"); if (probe.collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"FailureReason\":null}");
}

static int ah_uri_hex(unsigned char value) {
    return value >= '0' && value <= '9' ? value - '0' : value >= 'a' && value <= 'f' ? value - 'a' + 10 : value >= 'A' && value <= 'F' ? value - 'A' + 10 : -1;
}
static bool ah_uri_unreserved(unsigned char value) {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
        (value >= '0' && value <= '9') || value == '-' || value == '.' || value == '_' || value == '~';
}

static char *ah_adcs_uri_path(ah_arena &arena, const char *raw) {
    size_t length = ah_len(raw);
    if (length > (static_cast<size_t>(-1) - 1) / 3) return nullptr;
    char *out = static_cast<char *>(arena.alloc(length * 3 + 1)); if (!out) return nullptr;
    const char hex[] = "0123456789ABCDEF";
    size_t used = 0; bool query = false, fragment = false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char value = static_cast<unsigned char>(raw[i]);
        if (value == '%' && i + 2 < length && ah_uri_hex(raw[i + 1]) >= 0 && ah_uri_hex(raw[i + 2]) >= 0) {
            unsigned char decoded = static_cast<unsigned char>(ah_uri_hex(raw[i + 1]) * 16 + ah_uri_hex(raw[i + 2]));
            if (ah_uri_unreserved(decoded)) out[used++] = static_cast<char>(decoded);
            else { out[used++] = '%'; out[used++] = raw[i + 1]; out[used++] = raw[i + 2]; }
            i += 2; continue;
        }
        if (value == '#' && !fragment) fragment = true;
        if (value == '?' && !fragment) query = true;
        if (value == '\\' && !query && !fragment) value = '/';
        bool safe = ah_uri_unreserved(value);
        for (const char *p = ":/?#[]@!$&'()*+,;="; *p; ++p) if (value == static_cast<unsigned char>(*p)) safe = true;
        if (safe) out[used++] = static_cast<char>(value);
        else { out[used++] = '%'; out[used++] = hex[value >> 4]; out[used++] = hex[value & 15]; }
    }
    size_t path_end = 0; while (path_end < used && out[path_end] != '?' && out[path_end] != '#') ++path_end;
    if (path_end && out[0] == '/') {
        size_t read = 1, write = 1;
        while (read <= path_end) {
            size_t start = read; while (read < path_end && out[read] != '/') ++read;
            size_t size = read - start; bool slash = read < path_end;
            if (size == 1 && out[start] == '.') {   }
            else if (size == 2 && out[start] == '.' && out[start + 1] == '.') {
                if (write > 1 && out[write - 1] == '/') --write;
                while (write > 1 && out[write - 1] != '/') --write;
            } else {
                for (size_t i = 0; i < size; ++i) out[write++] = out[start + i];
                if (slash) out[write++] = '/';
            }
            if (!slash) break;
            ++read;
        }
        for (size_t i = path_end; i < used; ++i) out[write++] = out[i];
        used = write;
    }
    out[used] = 0; return out;
}

static void ah_adcs_http_endpoints(ah_graph &g, ah_buffer &b, ah_object *o, int collection) {
    if (!(collection & AH_CERT_SERVICES) || !g.host_selected(o->text("dNSHostName"))) { AH_TEXT(&b, "[]"); return; }
    const char *host = o->text("dNSHostName"), *ca = o->text("name");

    char *http_root = ah_concat(g.arena, "http://", host, "/certsrv/");
    char *https_root = ah_concat(g.arena, "https://", host, "/certsrv/");
    char *ces_original_path = ah_concat(g.arena, "/", ca, "_CES_Kerberos/service.svc");
    char *ces_uri_path = ah_adcs_uri_path(g.arena, ces_original_path);
    if (!ces_uri_path) { b.failed = true; return; }
    char *http_ces = ah_concat(g.arena, "http://", host, ces_original_path);
    char *https_ces = ah_concat(g.arena, "https://", host, ces_original_path);
    size_t request_size = 0; while (ces_uri_path[request_size] && ces_uri_path[request_size] != '#') ++request_size;
    char *ces_request_path = g.arena.copy(ces_uri_path, request_size);
    AH_TEXT(&b, "[");
    ah_adcs_endpoint(b, host, 80, "/certsrv/", http_root, "WebEnrollmentApplication", false);
    AH_TEXT(&b, ","); ah_adcs_endpoint(b, host, 443, "/certsrv/", https_root, "WebEnrollmentApplication", true);
    AH_TEXT(&b, ","); ah_adcs_endpoint(b, host, 80, ces_request_path, http_ces, "EnrollmentWebService", false);
    AH_TEXT(&b, ","); ah_adcs_endpoint(b, host, 443, ces_request_path, https_ces, "EnrollmentWebService", true);
    AH_TEXT(&b, "]");
}

static bool ah_resolve_certificate_template(ah_graph &, const char *, const char *, const char **, const char **, const char **);
static ah_object *ah_adcs_external_template(ah_graph &g, const char *property, const char *value) {
    const char *id = nullptr, *kind = nullptr, *name = nullptr;
    if (!ah_resolve_certificate_template(g, property, value, &id, &kind, &name) || !id || !kind) return nullptr;
    ah_object *object = g.arena.make<ah_object>();
    if (!object) return nullptr;
    object->id = g.arena.copy(id); object->kind = kind;
    object->type = L"certtemplates"; object->exported = true;
    if (name) g.directory.value(g.directory.attribute(object, "name"), name, ah_len(name));
    return object;
}
static ah_object *ah_adcs_template(ah_graph &g, const char *name) {
    if (!name || !*name) return nullptr;
    for (ah_object *candidate = g.directory.objects; candidate; candidate = candidate->next) {
        if (!ah_weq(candidate->type, L"certtemplates")) continue;
        if (ah_eq(candidate->text("cn"), name)) return candidate;
    }
    return ah_adcs_external_template(g, "cn", name);
}

static void ah_ca_bool_result(ah_buffer &b, bool collected, bool value, const char *reason) {
    AH_TEXT(&b, "{\"Value\":"); if (collected && value) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"Collected\":"); if (collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"FailureReason\":"); if (collected) AH_TEXT(&b, "null"); else ah_string(b, reason ? reason : "RegistryQueryFailed"); AH_TEXT(&b, "}");
}

static const char *ah_ace_access_type(unsigned char type) {
    if (type == 0) return "AccessAllowed";
    if (type == 1) return "AccessDenied";
    if (type == 5) return "AccessAllowedObject";
    if (type == 6) return "AccessDeniedObject";
    if (type == 9) return "AccessAllowedCallback";
    if (type == 10) return "AccessDeniedCallback";
    if (type == 11) return "AccessAllowedCallbackObject";
    if (type == 12) return "AccessDeniedCallbackObject";
    return "Unknown";
}

static ah_object *ah_adcs_template_oid(ah_graph &g, const char *oid) {
    if (!oid || !*oid) return nullptr;
    for (ah_object *candidate = g.directory.objects; candidate; candidate = candidate->next)
        if (ah_weq(candidate->type, L"certtemplates") && ah_eq(candidate->text("msPKI-Cert-Template-OID"), oid)) return candidate;
    return ah_adcs_external_template(g, "msPKI-Cert-Template-OID", oid);
}

static void ah_enrollment_restrictions(ah_graph &g, ah_buffer &b, ah_object *o) {
    AH_TEXT(&b, "["); bool first = true;
    if (!ah_sd_aces(o->enrollment_agent_rights, [&](const ah_ace &ace) {
        if (ace.opaque_size < 4) return;
        uint32_t count = ah_u32(ace.opaque), index = 4;
        struct target { char sid[192]; target *next; } *head = nullptr, **tail = &head;
        for (uint32_t i = 0; i < count; ++i) {
            if (index + 2 > ace.opaque_size) return;
            size_t sid_length = 8 + 4 * static_cast<size_t>(ace.opaque[index + 1]);
            if (sid_length > ace.opaque_size - index) return;
            target *item = g.arena.make<target>();
            if (!item || !ah_sid_string(item->sid, ace.opaque + index, sid_length)) return;
            *tail = item; tail = &item->next; index += sid_length;
        }
        bool all_templates = index >= ace.opaque_size;
        ah_object *cert_template = nullptr;
        if (!all_templates) {
            if ((ace.opaque_size - index) < 2 || (ace.opaque_size - index) % 2) return;
            wchar_t wide[256]; size_t chars = (ace.opaque_size - index - 2) / 2;
            if (chars >= sizeof(wide) / sizeof(wide[0])) return;
            size_t used = 0;
            for (size_t i = 0; i < chars; ++i) {
                wchar_t ch = static_cast<wchar_t>(ace.opaque[index + i * 2] | (ace.opaque[index + i * 2 + 1] << 8));
                if (ch) wide[used++] = ch;
            }
            wide[used] = 0;
            char *name = g.arena.utf8(wide);
            cert_template = ah_adcs_template(g, name);
            if (!cert_template) cert_template = ah_adcs_template_oid(g, name);
            if (!cert_template) return;
        }
        if (!first) { AH_TEXT(&b, ","); }
        first = false; AH_TEXT(&b, "{\"Template\":"); if (cert_template) ah_ref(b, cert_template); else AH_TEXT(&b, "null");
        AH_TEXT(&b, ",\"Agent\":"); if (!ah_ca_registry_principal(g, b, o, ace.sid)) AH_TEXT(&b, "null");
        AH_TEXT(&b, ",\"AllTemplates\":"); if (all_templates) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
        AH_TEXT(&b, ",\"AccessType\":"); ah_string(b, ah_ace_access_type(ace.type));
        AH_TEXT(&b, ",\"Targets\":["); bool target_first = true;
        for (target *item = head; item; item = item->next) {
            ah_buffer target_principal(4096);
            if (!ah_ca_registry_principal(g, target_principal, o, item->sid)) continue;
            if (!target_first) { AH_TEXT(&b, ","); }
            target_first = false; ah_append(&b, target_principal.data, target_principal.length);
        }
        AH_TEXT(&b, "]}");
    }, true)) b.failed = true;
    AH_TEXT(&b, "]");
}

static void ah_ca_registry_acl(ah_graph &g, ah_buffer &b, ah_object *o) {
    AH_TEXT(&b, "["); bool first = true;
    auto emit = [&](const char *sid, const char *right, bool inherited) {
        if (ah_ignore_sid(sid)) return;
        if (!first) { AH_TEXT(&b, ","); } first = false;
        ah_ca_registry_principal(g, b, o, sid, right, inherited);
    };
    const ah_value *sd = o->ca_security;
    if (sd && sd->size >= 20) {
        const unsigned char *data = reinterpret_cast<const unsigned char *>(sd->data);
        uint32_t offset = ah_u32(data + 4); char owner[192];
        if (offset) {
            if (offset >= sd->size || !ah_sid_string(owner, data + offset, sd->size - offset)) b.failed = true;
            else emit(owner, "Owns", false);
        }
    }
    if (!ah_ad_rule_aces(o->ca_security, [&](const ah_ace &ace) {
        if (ace.type == 1 || ace.type == 6) return;
        bool inherited = (ace.flags & 0x10) != 0;
        if (ace.mask & 1U) emit(ace.sid, "ManageCA", inherited);
        if (ace.mask & 2U) emit(ace.sid, "ManageCertificates", inherited);
        if (ace.mask & 0x200U) emit(ace.sid, "Enroll", inherited);
    })) b.failed = true;
    AH_TEXT(&b, "]");
}

static void ah_ca_registry_result(ah_graph &g, ah_buffer &b, ah_object *o) {
    if (!o->ca_registry_requested) { AH_TEXT(&b, "null"); return; }
    AH_TEXT(&b, "{\"CASecurity\":{\"Data\":");
    if (o->ca_security_collected && o->ca_security) ah_ca_registry_acl(g, b, o); else AH_TEXT(&b, "[]");
    AH_TEXT(&b, ",\"Collected\":"); bool security_collected = o->ca_security_collected;
    if (security_collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"FailureReason\":"); if (security_collected) AH_TEXT(&b, "null"); else ah_string(b, o->ca_security_failure ? o->ca_security_failure : "RegistryQueryFailed");
    AH_TEXT(&b, "},\"EnrollmentAgentRestrictions\":{\"Restrictions\":");
    if (o->enrollment_agent_collected && o->enrollment_agent_rights) ah_enrollment_restrictions(g, b, o); else AH_TEXT(&b, "[]");
    AH_TEXT(&b, ",\"Collected\":"); bool restrictions_collected = o->enrollment_agent_collected;
    if (restrictions_collected) AH_TEXT(&b, "true"); else AH_TEXT(&b, "false");
    AH_TEXT(&b, ",\"FailureReason\":"); if (restrictions_collected) AH_TEXT(&b, "null"); else ah_string(b, o->enrollment_agent_failure ? o->enrollment_agent_failure : "RegistryQueryFailed");
    AH_TEXT(&b, "},\"IsUserSpecifiesSanEnabled\":"); ah_ca_bool_result(b, o->san_collected, o->san_enabled, o->san_failure);
    AH_TEXT(&b, ",\"RoleSeparationEnabled\":"); ah_ca_bool_result(b, o->role_separation_collected, o->role_separation_enabled, o->role_separation_failure);
    AH_TEXT(&b, "}");
}

static void ah_adcs_node(ah_graph &g, ah_buffer &b, ah_object *o, int collection) {
    bool object_props = (collection & (AH_OBJECT_PROPS | AH_CERT_SERVICES)) != 0;
    bool acl = (collection & (AH_ACL | AH_CERT_SERVICES)) != 0;
    bool container = (collection & (AH_CONTAINER | AH_CERT_SERVICES)) != 0;
    AH_TEXT(&b, "{"); ah_fields node(b);
    node.key("Properties"); AH_TEXT(&b, "{"); ah_fields props(b);
    const char *account = ah_weq(o->type, L"issuancepolicies") ? o->text("displayName", o->text("cn", "UNKNOWN")) : o->text("name", "UNKNOWN");
    const char *owner_domain = g.object_domain(o), *owner_sid = g.object_domain_sid(o);
    props.text("domain", owner_domain);
    props.text("name", ah_upper(g.arena, ah_concat(g.arena, account, "@", owner_domain)));
    props.text("distinguishedname", ah_upper(g.arena, o->dn)); props.text("domainsid", owner_sid);
    ah_value *sd = o->values("nTSecurityDescriptor");
    bool protected_acl = acl && sd && sd->size >= 20 && (ah_u16(reinterpret_cast<unsigned char *>(sd->data) + 2) & 0x1000);
    if (acl) {
        props.boolean("doesanyacegrantownerrights", ah_owner_rights(g, o, false));
        props.boolean("doesanyinheritedacegrantownerrights", ah_owner_rights(g, o, true));
        props.boolean("isaclprotected", protected_acl);
    }
    if (object_props) ah_common_object_properties(g, b, props, o);
    auto close_properties = [&]() { AH_TEXT(&b, "}"); };
    if (ah_weq(o->type, L"rootcas")) {
        if (object_props) ah_adcs_cert_properties(g, b, props, o);
        close_properties(); AH_TEXT(&b, ",\"DomainSID\":"); ah_string(b, owner_sid);
    } else if (ah_weq(o->type, L"aiacas")) {
        if (object_props) {
        props.key("crosscertificatepair"); ah_adcs_binary_array(b, o->values("crossCertificatePair"));
        props.boolean("hascrosscertificatepair", o->values("crossCertificatePair") != nullptr);
        ah_adcs_cert_properties(g, b, props, o);
        }
        close_properties();
    } else if (ah_weq(o->type, L"enterprisecas")) {
        if (object_props) {
        ah_adcs_enum_property(b, props, "flags", o, "flags", 15U, nullptr, ah_adcs_ca_flags(g.arena, o), true);
        props.text("caname", o->values("name") ? o->text("name") : nullptr);
        props.text("dnshostname", o->values("dNSHostName") ? o->text("dNSHostName") : nullptr); ah_adcs_cert_properties(g, b, props, o);
        if (o->values("certificateTemplates")) {
        props.key("unresolvedpublishedtemplates"); AH_TEXT(&b, "[");
        bool first = true;
        for (ah_value *v = o->values("certificateTemplates"); v; v = v->next) if (!ah_adcs_template(g, v->data)) {
            if (!first) { AH_TEXT(&b, ","); } first = false; ah_string(b, v->data);
        }
        AH_TEXT(&b, "]");
        }
        }
        if ((collection & AH_CA_REGISTRY) && !o->ca_registry_requested && o->values("name") && o->values("dNSHostName") && g.host_selected(o->text("dNSHostName"))) ah_collect_ca_registry(g, o);
        if (collection & AH_CA_REGISTRY) {
        props.boolean("casecuritycollected", o->ca_security_collected);
        props.boolean("enrollmentagentrestrictionscollected", o->enrollment_agent_collected);
        props.boolean("isuserspecifiessanenabledcollected", o->san_collected);
        props.boolean("roleseparationenabledcollected", o->role_separation_collected);
        }
        close_properties(); AH_TEXT(&b, ",\"HostingComputer\":");
        bool host_requested = (collection & (AH_CA_REGISTRY | AH_CERT_SERVICES)) && o->values("name") && o->values("dNSHostName") && g.host_selected(o->text("dNSHostName"));
        ah_object *known_host = host_requested ? g.hosts.find(o->text("dNSHostName")) : nullptr;
        const char *hosting_sid = known_host ? known_host->id : nullptr;
        if (!hosting_sid && host_requested)
            hosting_sid = ah_session_lookup_host(g, o->text("dNSHostName"));
        if (hosting_sid && !ah_prefix(hosting_sid, "S-1-")) hosting_sid = nullptr;
        if (hosting_sid) {
            const char *display_name = ah_upper(g.arena, ah_concat(g.arena, account, "@", owner_domain));
            if (collection & AH_CERT_SERVICES) ah_track_call(g, o, "ProcessEnterpriseCA", "Success", display_name);
            if (collection & AH_CA_REGISTRY) {
                ah_object tracked = *o; tracked.id = const_cast<char *>(hosting_sid);
                ah_track_call(g, &tracked, "ProcessEnterpriseCA", "Success", display_name);
            }
        }
        if (hosting_sid) ah_string(b, hosting_sid); else AH_TEXT(&b, "null");
        node.key("CARegistryData"); ah_ca_registry_result(g, b, o);
        node.key("EnabledCertTemplates");
        if (object_props && o->values("certificateTemplates")) {
        AH_TEXT(&b, "["); bool first = true;
        for (ah_value *v = o->values("certificateTemplates"); v; v = v->next) {
            ah_object *target = ah_adcs_template(g, v->data);
            if (target && target->exported) { if (!first) { AH_TEXT(&b, ","); } first = false; ah_ref(b, target); }
        }
        AH_TEXT(&b, "]");
        } else AH_TEXT(&b, "null");
        node.key("HttpEnrollmentEndpoints");
        if ((collection & AH_CERT_SERVICES) && host_requested) ah_adcs_http_endpoints(g, b, o, collection); else AH_TEXT(&b, "null");
    } else if (ah_weq(o->type, L"ntauthstores")) {
        if (object_props && o->values("cACertificate")) {
        props.key("certthumbprints"); AH_TEXT(&b, "["); bool first = true;
        for (ah_value *certificate = o->values("cACertificate"); certificate; certificate = certificate->next) {
            if (!first) { AH_TEXT(&b, ","); } first = false; ah_string(b, ah_thumbprint(g.arena, certificate));
        }
        AH_TEXT(&b, "]");
        }
        close_properties(); AH_TEXT(&b, ",\"DomainSID\":"); ah_string(b, owner_sid);
    } else if (ah_weq(o->type, L"certtemplates")) {
        if (object_props) {
        uint32_t enrollment = static_cast<uint32_t>(ah_integer(o, "msPKI-Enrollment-Flag"));
        uint32_t schema = o->values("msPKI-Template-Schema-Version") ? static_cast<uint32_t>(ah_integer(o, "msPKI-Template-Schema-Version")) : 0;
        uint32_t name_flags = static_cast<uint32_t>(ah_integer(o, "msPKI-Certificate-Name-Flag"));
        props.text("validityperiod", ah_adcs_duration(g.arena, o, "pKIExpirationPeriod"));
        props.text("renewalperiod", ah_adcs_duration(g.arena, o, "pKIOverlapPeriod"));
        if (o->values("msPKI-Template-Schema-Version")) props.number("schemaversion", schema);
        props.nullable_text("displayname", o->text("displayName", nullptr)); props.nullable_text("oid", o->text("msPKI-Cert-Template-OID", nullptr));
        if (o->values("msPKI-Enrollment-Flag")) {
        ah_adcs_enum_property(b, props, "enrollmentflag", o, "msPKI-Enrollment-Flag", 0x000fffffU, "NONE", ah_adcs_enrollment_flags(g.arena, o));
        props.boolean("requiresmanagerapproval", (enrollment & 0x00000002U) != 0); props.boolean("nosecurityextension", (enrollment & 0x00080000U) != 0);
        }
        if (o->values("msPKI-Certificate-Name-Flag")) {
        ah_adcs_enum_property(b, props, "certificatenameflag", o, "msPKI-Certificate-Name-Flag", 0xffc1010fU, nullptr, ah_adcs_name_flags(g.arena, o));
        props.boolean("enrolleesuppliessubject", (name_flags & 0x00000001U) != 0);
        props.boolean("subjectaltrequireupn", (name_flags & 0x02000000U) != 0);
        props.boolean("subjectaltrequiredns", (name_flags & 0x08000000U) != 0);
        props.boolean("subjectaltrequiredomaindns", (name_flags & 0x00400000U) != 0);
        props.boolean("subjectaltrequireemail", (name_flags & 0x04000000U) != 0);
        props.boolean("subjectaltrequirespn", (name_flags & 0x00800000U) != 0);
        props.boolean("subjectrequireemail", (name_flags & 0x20000000U) != 0);
        }
        props.key("ekus"); ah_text_array(b, o->values("pKIExtendedKeyUsage"));
        props.key("certificateapplicationpolicy"); ah_text_array(b, o->values("msPKI-Certificate-Application-Policy"));
        props.key("certificatepolicy"); ah_text_array(b, o->values("msPKI-Certificate-Policy"));
        if (o->values("msPKI-RA-Signature")) props.number("authorizedsignatures", ah_integer(o, "msPKI-RA-Signature"));
        bool legacy_provider = (static_cast<uint32_t>(ah_integer(o, "msPKI-Private-Key-Flag")) & 0x00000010U) != 0;
        props.key("applicationpolicies"); ah_adcs_application_policies(b, o, schema, legacy_provider);
        props.key("issuancepolicies"); ah_text_array(b, o->values("msPKI-RA-Policies"));
        ah_value *effective = schema == 1 && o->values("pKIExtendedKeyUsage") ? o->values("pKIExtendedKeyUsage") : o->values("msPKI-Certificate-Application-Policy");
        props.key("effectiveekus"); ah_text_array(b, effective);
        bool authentication = !effective, schannel = !effective;
        for (ah_value *v = effective; v; v = v->next) {
            if (ah_eq(v->data, "1.3.6.1.5.5.7.3.2") || ah_eq(v->data, "2.5.29.37.0")) { authentication = true; schannel = true; }
            if (ah_eq(v->data, "1.3.6.1.4.1.311.20.2.2") || ah_eq(v->data, "1.3.6.1.5.2.3.4")) authentication = true;
        }
        props.boolean("authenticationenabled", authentication); props.boolean("schannelauthenticationenabled", schannel);
        }
        close_properties();
    } else if (ah_weq(o->type, L"issuancepolicies")) {
        const char *linked_id = nullptr, *linked_kind = nullptr;
        if (object_props && *o->text("msDS-OIDToGroupLink"))
            ah_resolve_directory_dn(g, o->text("msDS-OIDToGroupLink"), &linked_id, &linked_kind);
        if (object_props) {
        props.nullable_text("displayname", o->text("displayName", nullptr)); props.nullable_text("certtemplateoid", o->text("msPKI-Cert-Template-OID", nullptr));
        if (linked_id) props.text("oidgrouplink", linked_id);
        }
        close_properties(); AH_TEXT(&b, ",\"GroupLink\":"); if (linked_id) ah_ref(b, linked_id, linked_kind); else AH_TEXT(&b, "{\"ObjectIdentifier\":null,\"ObjectType\":\"Base\"}");
    } else {
        close_properties();
    }

    node.text("ObjectIdentifier", o->id);
    node.key("Aces"); if (acl) ah_ad_acl(g, b, o); else AH_TEXT(&b, "[]");
    node.boolean("IsACLProtected", protected_acl);
    node.boolean("IsDeleted", false);
    node.key("ContainedBy"); if (container) ah_directory_ref(g, b, ah_parent(o->dn)); else AH_TEXT(&b, "null");
    AH_TEXT(&b, "}");
}

static bool ah_adcs_file(ah_graph &g, ah_buffer &b, const wchar_t *type, const char *name, int collection) {
    AH_TEXT(&b, "{\"data\":["); unsigned int count = 0;
    for (ah_object *o = g.directory.objects; o && !b.failed && !g.arena.failed; o = o->next) if (ah_output_selected(g, o) && ah_weq(o->type, type)) {
        if (ah_weq(type, L"issuancepolicies") && !ah_eq(o->kind, "IssuancePolicy")) continue;
        if (count++) AH_TEXT(&b, ",");
        ah_adcs_node(g, b, o, collection);
    }
    AH_TEXT(&b, "],\"meta\":{"); ah_fields meta(b);
    meta.text("type", name); meta.number("count", count); meta.number("version", 6); meta.number("methods", ah_collection);
    AH_TEXT(&b, "}}");
    return !b.failed && !g.arena.failed;
}
