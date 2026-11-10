#include "../../common/core/collector.h"
#include "../../common/core/imports.hpp"
#include "../../common/core/buffer.hpp"
#include "core/directory.hpp"
#include "../../common/core/settings.hpp"
#include "../../common/core/observability.hpp"
#include "../../common/ldap/ldap_query.hpp"
#include "../../common/ldap/ldap_collect.hpp"
#include "../../common/core/options.hpp"
#include "../../common/ldap/ldap_connection.hpp"
#include "core/runtime.hpp"
#include "graph/graph.hpp"

static bool ah_collect_single(const ah_options &options, const ah_profile *profile) {
    ah_pretty_print = (options.runtime_flags & 256) != 0;
    ah_no_zip = (options.runtime_flags & 512) != 0;
    ah_random_filenames = (options.runtime_flags & 1024) != 0;
    ah_output_prefix = options.output_prefix; ah_zip_password = options.zip_password;
    ah_ldap_scope_control = nullptr;
    if (!*options.server || !*options.user || !options.tls || options.kerberos) {
        BeaconPrintf(CALLBACK_ERROR, "FreeIPA requires an explicit server and LDAPS simple bind"); return false;
    }
    ah_directory directory(ah_memory_limit(options.mib));
    ah_directory_runtime runtime(options);
    ah_ipa_runtime_scope scope(runtime);
    wchar_t *server = ah_wide(options.server), *base = ah_wide(options.base);
    LDAP *ld = nullptr;
    bool complete = true, success = false;
    ULONG status = LDAP_SUCCESS;
    if (!server || !base) goto cleanup;
    ld = ah_open_ipa_directory(server, status);
    if (!ld) { BeaconPrintf(CALLBACK_ERROR, "LDAP connection/authentication failed: %u", status); goto cleanup; }
    if (wchar_t *actual_server = ah_root(ld, L"dNSHostName")) {
        if (auto *item = ah_ipa_handle(ah_ldap_current(ld))) {
            ah_free(item->server); item->server = actual_server;
        } else ah_free(actual_server);
    }
    if (!*base) { ah_free(base); base = ah_root(ld, L"namingContexts"); }
    if (!base || !*base) { BeaconPrintf(CALLBACK_ERROR, "Cannot select naming context; specify --base-dn"); goto cleanup; }
    for (unsigned int i = 0; i < profile->query_count && !directory.arena.failed; ++i) {
        const ah_query &query = profile->queries[i];
        if (!ah_dataset_page(directory, ld, &query, base, profile->attributes, nullptr,
            static_cast<unsigned int>(options.pages), query.filter, false, false, false, nullptr, {})) {
            complete = false; break;
        }
    }
    if (!complete || directory.arena.failed) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP collection incomplete or memory limit reached; no archive sent. Check LDAP errors and --max-mib.");
    } else {
        success = ah_export(directory, profile, base, options.output, ah_memory_limit(options.mib));
        if (!success) BeaconPrintf(CALLBACK_ERROR, "Graph/ZIP generation failed or memory limit reached; no archive sent.");
    }
cleanup:
    if (ld) ah_close_directory(ld);
    ah_free(server); ah_free(base);
    return success;
}

static void ah_collect(char *args, int length, const ah_profile *profile) {
    ah_verbosity = 2;
    ah_telemetry_enabled = false;
    ah_options options = {};

    const ah_wire_collections wire_modes = {23884779, 17040101, 66057215};
    if (!ah_unpack(args, length, options, wire_modes)) { BeaconPrintf(CALLBACK_ERROR, "Invalid AdaptiHound argument buffer or options"); return; }
    ah_verbosity = options.verbosity;
    ah_telemetry_enabled = ah_telemetry(options);
    if (options.legacy_layout) BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: legacy AxScript arguments; reload the extension to enable current options");
    if (options.collect_all || *options.computers || *options.domain || options.search_forest || options.recurse_domains || options.loop || options.skip_port_scan || options.skip_password_age_check || options.stealth || options.exclude_dcs || (options.runtime_flags&(14591|ah_memory_auto_flag)) || (options.option_presence&(767|ah_file_cache_flag)) || *options.cache_name || *options.ldap_username || *options.ldap_filter || *options.override_username || *options.real_dns_name || options.ssl_port || options.throttle || options.jitter) {
        BeaconPrintf(CALLBACK_ERROR, "Additional LDAP properties, target filters, loops and availability options require the AD backend"); return;
    }
    ah_memory_scope memory(ah_memory_limit(options.mib));
    ah_observability observations(options.status_interval, (options.option_presence & 1) != 0,
        options.output_prefix, options.server, ah_telemetry_enabled);
    if (!observations.valid()) return;
    BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: collecting FreeIPA");
    ah_observe_begin_pass();
    ah_collect_single(options, profile);
    ah_observe_end_pass();
    observations.finish();
    ah_log_telemetry("AdaptiHound: BOF-owned heap peak %llu bytes; allocation failures %llu",
        static_cast<unsigned long long>(memory.budget.peak()), static_cast<unsigned long long>(memory.budget.allocation_failures()));
    if (memory.budget.allocation_failures() && !ah_telemetry_enabled)
        BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: memory allocation failures occurred; check collection completeness");
}
