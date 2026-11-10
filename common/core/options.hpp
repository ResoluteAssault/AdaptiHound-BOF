#pragma once

struct ah_wire_collections { int defaults, dc_only, all; };
static char *ah_argument(datap *parser) {
    if (parser->length < 4) return NULL;
    const unsigned char *p = (const unsigned char *)parser->buffer;
    unsigned int count = (unsigned int)p[0] | (unsigned int)p[1] << 8 | (unsigned int)p[2] << 16 | (unsigned int)p[3] << 24;
    if (!count || count > (unsigned int)parser->length - 4) return NULL;
    int n = 0; char *s = BeaconDataExtract(parser, &n);
    if (!s || n <= 0 || s[n - 1] != 0) return NULL;
    for (int i = 0; i + 1 < n; ++i) if (!s[i]) return NULL;
    return s;
}

#include "timespan.hpp"
struct ah_options {
    char *server, *base, *output, *user, *password, *domain, *computers;
    int tls, kerberos, port, pages, mib, collection, search_forest, recurse_domains;
    int collect_all, skip_port_scan, skip_password_age_check, port_scan_timeout;
    int loop, loop_duration, loop_interval;
    int stealth, exclude_dcs;
    int runtime_flags, ssl_port, throttle, jitter, threads, status_interval;
    char *ldap_filter, *ldap_username, *ldap_password, *local_admin_username, *local_admin_password;
    char *override_username, *real_dns_name, *output_prefix, *zip_password, *cache_name;
    char *loop_duration_text, *loop_interval_text, *computer_file_path, *computer_file_text;
    int option_presence, verbosity;
    int64_t loop_duration_ticks, loop_interval_ticks;
    bool legacy_layout;
    int wire_version;
};
static size_t ah_memory_limit(int mib) { return static_cast<size_t>(mib) * 1024 * 1024; }
static constexpr int ah_memory_auto_flag = 16384;
static bool ah_memory_auto(const ah_options &options) { return (options.runtime_flags & ah_memory_auto_flag) != 0; }
static constexpr int ah_telemetry_flag = 1024;
static bool ah_telemetry(const ah_options &options) { return (options.option_presence & ah_telemetry_flag) != 0; }
static constexpr int ah_file_cache_flag = 2048;
static bool ah_file_cache(const ah_options &options) { return (options.option_presence & ah_file_cache_flag) != 0; }
static inline size_t ah_memory_workspace(const ah_options &options) {
    const size_t maximum = ah_memory_limit(options.mib);
    constexpr size_t initial = 32 * 1024 * 1024;
    return ah_memory_auto(options) && (!maximum || maximum > initial) ? initial : maximum;
}
static bool ah_unpack(char *args, int length, ah_options &o, const ah_wire_collections &modes) {
    if (!args || length < 4) return false;
    datap parser; BeaconDataParse(&parser, args, length);
    o.server = ah_argument(&parser); o.base = ah_argument(&parser); o.output = ah_argument(&parser);
    o.user = ah_argument(&parser); o.password = ah_argument(&parser);
    int remaining = BeaconDataLength(&parser);
    if (!o.server || !o.base || !o.output || !o.user || !o.password || remaining < 20) return false;
    o.tls = BeaconDataInt(&parser); o.kerberos = BeaconDataInt(&parser); o.port = BeaconDataInt(&parser);
    o.pages = BeaconDataInt(&parser); o.mib = BeaconDataInt(&parser);
    o.computers = const_cast<char *>(""); o.collect_all = 0;
    o.skip_port_scan = o.skip_password_age_check = o.loop = 0;
    o.stealth = o.exclude_dcs = 0;
    o.port_scan_timeout = 10000; o.loop_duration = 7200; o.loop_interval = 30;
    o.runtime_flags = o.ssl_port = o.throttle = o.jitter = 0; o.threads = 50; o.status_interval = 30000; o.wire_version=0;
    o.ldap_filter = o.ldap_username = o.ldap_password = o.local_admin_username = o.local_admin_password = const_cast<char *>("");
    o.override_username = o.real_dns_name = o.output_prefix = o.zip_password = o.cache_name = const_cast<char *>("");
    o.loop_duration_text = o.loop_interval_text = o.computer_file_path = o.computer_file_text = const_cast<char *>("");
    o.option_presence = 0; o.verbosity = 2;
    o.legacy_layout = remaining == 20 || remaining == 24;
    if (o.legacy_layout) {

        o.collection = remaining == 20 ? modes.defaults : BeaconDataInt(&parser);
        if (remaining == 24 && o.collection >= 0 && o.collection <= 2) {
            const int legacy_modes[] = {modes.dc_only, modes.defaults, modes.all};
            o.collection = legacy_modes[o.collection];
        }
        o.domain = const_cast<char *>(""); o.search_forest = 0; o.recurse_domains = 0;
    } else {
        if (remaining < 24) return false;
        o.collection = BeaconDataInt(&parser); o.domain = ah_argument(&parser);
        if (!o.domain || BeaconDataLength(&parser) < 8) return false;
        o.search_forest = BeaconDataInt(&parser); o.recurse_domains = BeaconDataInt(&parser);
        if (BeaconDataLength(&parser)) {
            if (BeaconDataLength(&parser) < 13) return false;
            int version = BeaconDataInt(&parser);
            if (version < 1 || version > 8) return false;
            o.wire_version=version;
            int flags = BeaconDataInt(&parser);
            if (flags & ~(version == 1 ? 1 : 63)) return false;
            o.collect_all = flags & 1; o.computers = ah_argument(&parser);
            if (!o.computers || (version < 5 && ah_len(o.computers) > 262144)) return false;
            if (version >= 2) {
                if (BeaconDataLength(&parser) < 12) return false;
                o.skip_port_scan = (flags & 2) != 0; o.skip_password_age_check = (flags & 4) != 0; o.loop = (flags & 8) != 0;
                o.stealth = (flags & 16) != 0; o.exclude_dcs = (flags & 32) != 0;
                o.loop_duration = BeaconDataInt(&parser); o.loop_interval = BeaconDataInt(&parser); o.port_scan_timeout = BeaconDataInt(&parser);
            }
            if (version >= 3) {
                if (BeaconDataLength(&parser) < 4) return false;
                o.runtime_flags = BeaconDataInt(&parser);
                if (o.runtime_flags & ~(version >= 6 ? 32767 : version >= 4 ? 16383 : 4095)) return false;
                char **strings[] = {&o.ldap_filter, &o.ldap_username, &o.ldap_password, &o.local_admin_username, &o.local_admin_password,
                    &o.override_username, &o.real_dns_name, &o.output_prefix, &o.zip_password, &o.cache_name};
                for (char **value : strings) { *value = ah_argument(&parser); if (!*value || (version < 5 && ah_len(*value) > 262144)) return false; }
                if (BeaconDataLength(&parser) < 20 || (version < 5 && BeaconDataLength(&parser) != 20)) return false;
                o.ssl_port = BeaconDataInt(&parser); o.throttle = BeaconDataInt(&parser); o.jitter = BeaconDataInt(&parser);
                o.threads = BeaconDataInt(&parser); o.status_interval = BeaconDataInt(&parser);
                if (version >= 5) {
                    char **tail[] = {&o.loop_duration_text, &o.loop_interval_text, &o.computer_file_path, &o.computer_file_text};
                    for (char **value : tail) { *value = ah_argument(&parser); if (!*value) return false; }
                    if (BeaconDataLength(&parser) != 8) return false;
                    o.option_presence = BeaconDataInt(&parser); o.verbosity = BeaconDataInt(&parser);
                    if (o.option_presence & ~(version >= 8 ? 4095 : version >= 7 ? 2047 : 1023)) return false;
                }
            }
            if (BeaconDataLength(&parser)) return false;
        }
    }
    size_t n = ah_len(o.output);
    if (n && (n < 5 || !ah_eq(o.output + n - 4, ".zip"))) return false;
    for (const char *c = o.output; *c; ++c) if (*c == '/' || *c == '\\' || *c == ':' || static_cast<unsigned char>(*c) < 32) return false;
    o.loop_duration_ticks = static_cast<int64_t>(o.loop_duration) * 10000000LL;
    o.loop_interval_ticks = static_cast<int64_t>(o.loop_interval) * 10000000LL;
    if (o.wire_version >= 5 && (!ah_timespan_parse(o.loop_duration_text, o.loop_duration_ticks, (o.option_presence & 2) != 0) ||
        !ah_timespan_parse(o.loop_interval_text, o.loop_interval_ticks, (o.option_presence & 4) != 0))) return false;
    if (o.loop_duration_ticks == 0) o.loop_duration_ticks = 72000000000LL;
    if (o.loop_interval_ticks == 0) o.loop_interval_ticks = 300000000LL;
    const bool local_user_present = o.wire_version >= 5 ? (o.option_presence & 8) != 0 : (o.runtime_flags & 16) != 0;
    const bool local_password_present = o.wire_version >= 5 ? (o.option_presence & 16) != 0 : (o.runtime_flags & 16) != 0;
    return (o.tls == 0 || o.tls == 1) && (o.kerberos == 0 || o.kerberos == 1) &&
        (o.search_forest == 0 || o.search_forest == 1) && (o.recurse_domains == 0 || o.recurse_domains == 1) &&
        o.port >= 0 && o.port <= 65535 && o.pages >= 1 && o.pages <= 1000 && o.mib >= 0 && static_cast<uint64_t>(o.mib) <= SIZE_MAX / (1024 * 1024) &&
        (!ah_memory_auto(o) || o.wire_version >= 6) &&
        (!ah_telemetry(o) || o.wire_version >= 7) &&
        (!ah_file_cache(o) || (o.wire_version >= 8 && !(o.runtime_flags & 4096))) &&
        (!*o.cache_name || ah_file_cache(o) || (o.runtime_flags & 4096)) &&
        o.collection >= 0 && !(o.collection & ~modes.all) && (!o.loop || o.loop_interval_ticks > -10000LL) && o.port_scan_timeout >= 1 &&
        o.ssl_port >= 0 && o.ssl_port <= 65535 && o.throttle >= 0 && o.jitter >= 0 && o.jitter <= 100 && o.threads >= 1 && o.status_interval >= 1 &&
        (!*o.ldap_password || *o.ldap_username) && (!*o.user || !*o.ldap_username) && (o.wire_version>=4 || !*o.cache_name) &&
        (!(o.runtime_flags&16)||(local_user_present&&local_password_present)) &&
        ((o.runtime_flags&16)||(!local_user_present&&!local_password_present&&!*o.local_admin_username&&!*o.local_admin_password)) &&
        (!(o.option_presence&32)||!(o.option_presence&64)) && (!(o.option_presence&64)||*o.computer_file_path) &&
        (!(o.option_presence&96)||(o.runtime_flags&128)) && (!*o.user || (o.tls && !o.kerberos && *o.password)) && (*o.user || !*o.password);
}
