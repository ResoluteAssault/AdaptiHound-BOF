#pragma once
#include "archive_parts.hpp"

// A batch owns its LDAP objects, graph indexes and host results only until this
// exporter returns. Across batches retain only the finite well-known-principal
// set; complete JSON rows go straight to the multipart writer.
class ah_batch_output final {
    enum : size_t { principal_count = sizeof(ah_token_principals) / sizeof(ah_token_principals[0]) };
    struct owner final {
        const char *domain = nullptr, *sid = nullptr;
        bool selected[principal_count] = {};
    };
    ah_archive_parts &parts;
    size_t maximum;
    ah_arena arena;
    owner owners[2];
    uint64_t call_part = 0;
    char timestamp[16] = {};
    bool invalid = false, finalized = false;

    bool fail(const char *reason) {
        if (!invalid) BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: bounded graph export failed: %s", reason);
        invalid = true;
        return false;
    }
    owner *remember_owner(const char *domain, const char *sid) {
        if (!domain || !*domain) { fail("missing well-known principal owner"); return nullptr; }
        owner *empty = nullptr;
        for (auto &candidate : owners) {
            if (!candidate.domain) { if (!empty) empty = &candidate; continue; }
            if (!ah_eq(candidate.domain, domain)) continue;
            if (candidate.sid && *candidate.sid && sid && *sid && !ah_eq(candidate.sid, sid)) {
                fail("well-known principal owner SID changed"); return nullptr;
            }
            if ((!candidate.sid || !*candidate.sid) && sid && *sid) candidate.sid = arena.copy(sid);
            return arena.failed ? nullptr : &candidate;
        }
        if (!empty) { fail("too many well-known principal owner domains"); return nullptr; }
        empty->domain = arena.copy(domain);
        empty->sid = sid && *sid ? arena.copy(sid) : nullptr;
        return arena.failed ? nullptr : empty;
    }
    bool remember(ah_graph &graph, const ah_object *object) {
        if (!object || !ah_builtin(object->raw_sid)) return true;
        size_t index = 0;
        for (; index < principal_count; ++index) if (ah_eq(ah_token_principals[index].sid, object->raw_sid)) break;
        if (index == principal_count) return fail("unknown well-known principal");
        owner *target = remember_owner(graph.object_domain(object), graph.object_domain_sid(object));
        if (!target) return false;
        target->selected[index] = true;
        return true;
    }
    bool remembered(ah_graph &graph, const ah_object *object) const {
        if (!object || !ah_builtin(object->raw_sid)) return false;
        const char *domain = graph.object_domain(object);
        for (const auto &candidate : owners) if (candidate.domain && ah_eq(candidate.domain, domain))
            for (size_t i = 0; i < principal_count; ++i)
                if (candidate.selected[i] && ah_eq(ah_token_principals[i].sid, object->raw_sid)) return true;
        return false;
    }
    bool emit_calls(const ah_directory &directory) {
        if (!ah_track_computer_calls || !directory.call_status) return true;
        // A status file can be split independently of the graph ZIP parts. No
        // row from a prior batch is copied into this exporter.
        const size_t target = maximum && maximum / 32 < 65536 ? maximum / 32 : 65536;
        ah_buffer csv(maximum, 4096);
        const char *header = "ComputerName,Task,Status,ObjectID\r\n";
        ah_append(&csv, header, ah_len(header));
        auto deliver = [&]() {
            if (csv.failed || csv.length > static_cast<size_t>(INT32_MAX) || call_part == UINT64_MAX) return false;
            char digits[32], stem[96];
            const char *number = ah_decimal(digits + sizeof(digits), ++call_part);
            size_t length = 0;
            const char *prefix = "compstatus-part";
            for (const char *p = prefix; *p; ++p) stem[length++] = *p;
            for (size_t i = ah_len(number); i < 6; ++i) stem[length++] = '0';
            for (const char *p = number; *p; ++p) stem[length++] = *p;
            stem[length] = 0;
            ah_arena names(maximum, 512);
            char *name = ah_output_name(names, stem, "csv", timestamp);
            if (!name || names.failed) return false;
            AxDownloadMemory(name, csv.data, static_cast<int>(csv.length));
            csv.length = 0;
            ah_append(&csv, header, ah_len(header));
            return !csv.failed;
        };
        for (const ah_call_status *row = directory.call_status; row; row = row->next) {
            ah_csv_cell(csv, row->computer); AH_TEXT(&csv, ", ");
            ah_csv_cell(csv, row->task); AH_TEXT(&csv, ", ");
            ah_csv_cell(csv, row->status); AH_TEXT(&csv, ", ");
            ah_csv_cell(csv, row->object_id); AH_TEXT(&csv, "\r\n");
            if (csv.failed || (csv.length >= target && !deliver())) return false;
        }
        return csv.length == ah_len(header) || deliver();
    }
    bool validate(const ah_object *object, const ah_buffer &json) {
        if (!object->id || !*object->id || json.failed || !json.data || !json.length) return false;
        ah_json_slice source{json.data, json.data + json.length}, complete, identifier, properties, dn, members;
        ah_combined_json parser(source);
        if (!parser.value(complete) || !parser.done() ||
            !ah_combined_json::member(source, "ObjectIdentifier", identifier) ||
            !ah_combined_json::member(source, "Properties", properties) ||
            properties.size() < 2 || *properties.begin != '{') return false;
        ah_buffer expected(maximum, 256);
        ah_string(expected, object->id);
        if (expected.failed || identifier.size() != expected.length) return false;
        for (size_t i = 0; i < expected.length; ++i) if (identifier.begin[i] != expected.data[i]) return false;
        const bool has_dn = ah_combined_json::member(properties, "distinguishedname", dn);
        if (has_dn && (dn.size() < 2 || *dn.begin != '"' || dn.end[-1] != '"')) return false;
        if ((*object->dn != 0) != (has_dn && dn.size() > 2)) return false;
        if (ah_eq(object->raw_sid, "S-1-5-9") && !ah_combined_json::member(source, "Members", members)) return false;
        return true;
    }
    struct context final { ah_batch_output &output; ah_graph &source; };
    static bool capture(void *opaque, const ah_object *object, const ah_buffer &json, ah_graph &local) {
        if (object->consumer_failed) return true;
        auto &state = *static_cast<context *>(opaque);
        if (!state.output.validate(object, json)) return state.output.fail("invalid serialized graph row");
        if (!state.output.parts.append(ah_output_dataset(object), json)) return false;
        if (*object->dn && !state.output.remember(local, object)) return false;
        for (auto *reference = local.output_references; reference; reference = reference->next)
            if (!state.output.remember(state.source, state.source.sids.find(reference->id))) return false;
        if (!state.output.emit_calls(local.directory) || state.source.arena.failed) return false;
        ah_observe_object_completed();
        ah_log_level(0, "Consumer completed %s (%s)", object->id, object->kind);
        return true;
    }
    static bool select_builtin(ah_graph &graph, const ah_object *object) {
        return !*object->dn && ah_builtin(object->raw_sid) && ah_output_selected(graph, object) && ah_output_dataset(object);
    }
    bool initialize(ah_directory &directory, const ah_profile *profile, const wchar_t *base,
        const wchar_t *dc, int methods, const char *forest_root_id, ah_graph &graph) {
        if (invalid || finalized || !parts.valid() || !profile || !profile->security_descriptors || !base)
            return fail("invalid multipart graph state");
        ah_current_dc = dc;
        ah_collection = methods;
        ah_forest_root_id = forest_root_id;
        if (!ah_ad_wellknown(directory) || !graph.init(base)) return fail("cannot resolve batch graph identifiers");
        if (!remember_owner(graph.domain, graph.root->id)) return fail("cannot retain domain identity");
        if (!graph.select_computers(ah_stealth || ah_computer_file_mode ? "" : ah_computer_targets))
            return fail("cannot select batch computers");
        for (ah_object *object = directory.objects; object; object = object->next)
            if (!*object->dn && ah_builtin(object->raw_sid)) object->exported = false;
        return !directory.arena.failed;
    }
    bool export_objects(ah_graph &graph, ah_object_pool::selected_fn selected) {
        context state{*this, graph};
        ah_object_pool pool(graph, maximum);
        const bool diagnostics = ah_host_diagnostics;
        ah_host_diagnostics = false;
        // One context at a time releases derived attributes, reference lookups
        // and the row buffer before the next object is serialized.
        const bool success = pool.run(graph.directory.objects, 1, selected, ah_serialize_output_object, capture, &state);
        ah_host_diagnostics = diagnostics;
        if (!success) {
            BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: bounded object processing failed (worker status %u)", pool.error());
            return fail("object serialization or part output did not complete");
        }
        return emit_calls(graph.directory) && !graph.arena.failed && !arena.failed && parts.valid();
    }
public:
    ah_batch_output(ah_archive_parts &output, size_t limit) : parts(output), maximum(limit), arena(limit, 512) {
        if (!ah_output_timestamp(timestamp)) fail("cannot create status output timestamp");
    }
    bool valid() const { return !invalid && !arena.failed && parts.valid(); }
    bool export_batch(ah_directory &directory, const ah_profile *profile, const wchar_t *base,
        const wchar_t *dc, int methods, const char *forest_root_id) {
        ah_graph graph(directory, true);
        if (!initialize(directory, profile, base, dc, methods, forest_root_id, graph)) return false;
        ah_host_pool hosts(graph, maximum);
        if ((ah_computer_collection(methods) || (methods & AH_LDAP_SERVICES)) &&
            !hosts.collect(dc, methods, ah_threads, ah_host_collection_selected)) return fail("host collection did not complete");
        if ((methods & AH_GPO_LOCAL_GROUP) && !ah_prepare_gpo_output(graph, dc)) return fail("GPO processing did not complete");
        if (!export_objects(graph, ah_parallel_output_selected)) return fail("batch did not complete");
        return true;
    }
    bool export_builtins(ah_directory &support, const ah_profile *profile, const wchar_t *base,
        const wchar_t *dc, int methods, const char *forest_root_id) {
        ah_graph graph(support, true);
        if (!initialize(support, profile, base, dc, methods, forest_root_id, graph)) return false;
        // Support contains every selected DC, so the single forest-owned
        // Enterprise Domain Controllers row has the complete member union.
        for (ah_object *object = support.objects; object; object = object->next)
            if (!*object->dn && ah_builtin(object->raw_sid)) object->exported = remembered(graph, object);
        if (!export_objects(graph, select_builtin)) return fail("well-known principal export did not complete");
        finalized = true;
        return true;
    }
    ah_batch_output(const ah_batch_output &) = delete;
    ah_batch_output &operator=(const ah_batch_output &) = delete;
};
