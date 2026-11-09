#pragma once
#include "../../../common/output/archive_output.hpp"
#include "../../../common/output/json.hpp"
#include <new>

// Each callback borrows the buffer for the duration of the call.  Acceptance by
// the callback is not an acknowledgement from Downloads or the remote server.
class ah_archive_parts final {
public:
    using sink_fn = bool (*)(void *, char *, const ah_buffer &);
private:
    struct format_state final {
        bool pretty = false, quoted = false, escaped = false, pending_open = false;
        unsigned int depth = 0;
        char previous = 0;
        template<typename Writer> bool indentation(Writer &writer) {
            if (!writer.write("\n", 1)) return false;
            for (unsigned int i = 0; i < depth; ++i) if (!writer.write("  ", 2)) return false;
            return true;
        }
        template<typename Writer> bool write(const char *text, size_t length, Writer &writer) {
            if (!pretty) return writer.write(text, length);
            for (size_t i = 0; i < length; ++i) {
                const char c = text[i];
                if (quoted) {
                    if (!writer.write(&c, 1)) return false;
                    if (escaped) escaped = false;
                    else if (c == '\\') escaped = true;
                    else if (c == '"') { quoted = false; previous = '"'; }
                    continue;
                }
                if (static_cast<unsigned char>(c) <= 32) continue;
                if (pending_open) {
                    if (c != '}' && c != ']' && !indentation(writer)) return false;
                    pending_open = false;
                }
                if (c == '"') { quoted = true; if (!writer.write(&c, 1)) return false; previous = c; continue; }
                if (c == '{' || c == '[') {
                    if (++depth > 256 || !writer.write(&c, 1)) return false;
                    pending_open = true; previous = c; continue;
                }
                if (c == '}' || c == ']') {
                    if (!depth) return false;
                    --depth;
                    if (previous != '{' && previous != '[' && !indentation(writer)) return false;
                    if (!writer.write(&c, 1)) return false;
                    previous = c; continue;
                }
                if (c == ',') {
                    if (!writer.write(&c, 1) || !indentation(writer)) return false;
                    previous = c; continue;
                }
                if (c == ':') {
                    if (!writer.write(": ", 2)) return false;
                    previous = c; continue;
                }
                if (!writer.write(&c, 1)) return false;
                previous = c;
            }
            return true;
        }
        bool complete() const { return !pretty || (!depth && !quoted && !escaped && !pending_open); }
    };
    struct counter final {
        size_t bytes = 0;
        bool write(const char *, size_t length) { return ah_size_add(bytes, length, bytes); }
    };
    struct consumer final {
        ah_archive_parts &owner;
        bool write(const char *text, size_t length) { return owner.queue(text, length); }
    };

    ah_arena arena;
    ah_buffer manifest, name, raw, formatted;
    ah_zip *zip = nullptr;
    sink_fn sink;
    void *opaque;
    const char *root = nullptr, *prefix = nullptr;
    const char *password;
    const char *failure = nullptr;
    size_t raw_target, row_limit, buffer_limit = 0, payload_bytes = 0;
    int methods, current = -1;
    uint64_t emitted_parts = 0, emitted_records = 0, accepted_records = 0, pending_records = 0;
    uint64_t counts[16] = {};
    uint32_t checksum = 0xffffffffU;
    bool no_zip, pretty, invalid = false, finalized = false, completed = false;
    format_state format;

    static const char *dataset_name(size_t index) {
        const char *names[] = {
            "users", "computers", "groups", "domains", "ous", "gpos", "containers", "rootcas",
            "aiacas", "enterprisecas", "ntauthstores", "certtemplates", "issuancepolicies", "sites", "siteservers", "sitesubnets"
        };
        return index < 16 ? names[index] : nullptr;
    }
    static int dataset_index(const char *dataset) {
        if (dataset) for (int i = 0; i < 16; ++i) if (ah_eq(dataset, dataset_name(static_cast<size_t>(i)))) return i;
        return -1;
    }
    bool fail(const char *reason) {
        if (!failure) failure = reason;
        invalid = true;
        return false;
    }
    static void release(ah_buffer &buffer) {
        ah_free(buffer.data); buffer.data = nullptr; buffer.length = buffer.capacity = 0; buffer.failed = false;
    }
    void discard() {
        if (zip) { zip->~ah_zip(); ah_free(zip); zip = nullptr; }
        release(raw); release(formatted);
        current = -1; pending_records = 0; payload_bytes = 0;
        format = {}; format.pretty = pretty;
    }
    bool make_name(uint64_t part, const char *dataset, const char *extension) {
        if (!root || name.failed) return false;
        name.length = 0;
        ah_append(&name, root, ah_len(root));
        if (dataset) { AH_TEXT(&name, "-"); ah_append(&name, dataset, ah_len(dataset)); }
        if (part) {
            AH_TEXT(&name, "-part");
            char digits[32]; const char *number = ah_decimal(digits + sizeof(digits), part);
            const size_t width = ah_len(number);
            for (size_t i = width; i < 6; ++i) AH_TEXT(&name, "0");
            ah_append(&name, number, width);
        } else AH_TEXT(&name, ".manifest");
        AH_TEXT(&name, "."); ah_append(&name, extension, ah_len(extension)); AH_TEXT(&name, "\0");
        return !name.failed;
    }
    bool store(const char *text, size_t length) {
        if (no_zip) { ah_append(&raw, text, length); return !raw.failed; }
        return zip && zip->write(text, length);
    }
    bool drain_format() {
        if (formatted.failed || (formatted.length && !store(formatted.data, formatted.length))) return false;
        formatted.length = 0;
        return true;
    }
    bool queue(const char *text, size_t length) {
        if (!pretty) return store(text, length);
        while (length) {
            const size_t available = formatted.limit - formatted.length;
            const size_t take = length < available ? length : available;
            ah_append(&formatted, text, take);
            if (formatted.failed) return false;
            text += take; length -= take;
            if (formatted.length == formatted.limit && !drain_format()) return false;
        }
        return true;
    }
    bool write(const char *text, size_t length) {
        consumer output{*this};
        return format.write(text, length, output);
    }
    bool start(int dataset) {
        if (current >= 0 || !valid() || emitted_parts >= static_cast<uint64_t>(INT64_MAX)) return fail("cannot start another part");
        current = dataset;
        format = {}; format.pretty = pretty;
        if (!no_zip) {
            zip = ah_alloc<ah_zip>(sizeof(ah_zip));
            if (!zip) return fail("cannot allocate ZIP part");
            new (zip) ah_zip(buffer_limit, password);
            if (!make_name(emitted_parts + 1, dataset_name(static_cast<size_t>(dataset)), "json") || !zip->begin(name.data))
                return fail("cannot create ZIP entry");
        }
        if (!write("{\"data\":[", 9)) return fail("cannot write part header");
        return true;
    }
    bool row_size(const ah_buffer &row, size_t &length) const {
        format_state projected = format;
        counter output;
        if ((pending_records && !projected.write(",", 1, output)) || !projected.write(row.data, row.length, output)) return false;
        if (pretty && (projected.depth != 2 || projected.quoted || projected.escaped || projected.pending_open)) return false;
        length = output.bytes;
        return true;
    }
    bool deliver(char *filename, const ah_buffer &body) {
        if (body.failed || body.length > static_cast<size_t>(INT32_MAX) || (!body.data && body.length)) return false;
        if (sink) return sink(opaque, filename, body);
        AxDownloadMemory(filename, body.data, static_cast<int>(body.length));
        return true;
    }
    uint32_t part_checksum(const ah_buffer &body) const {
        uint32_t value = checksum;
        const uint64_t number = emitted_parts + 1, length = body.length;
        for (unsigned int i = 0; i < 8; ++i) value = ah_zip_crc_byte(value, static_cast<unsigned char>(number >> (8 * i)));
        for (unsigned int i = 0; i < 8; ++i) value = ah_zip_crc_byte(value, static_cast<unsigned char>(length >> (8 * i)));
        for (size_t i = 0; i < body.length; ++i) value = ah_zip_crc_byte(value, static_cast<unsigned char>(body.data[i]));
        return value;
    }
    bool emit_manifest(bool success) {
        if (!manifest.data || !root || !prefix) return false;
        manifest.length = 0;
        AH_TEXT(&manifest, "{"); ah_fields fields(manifest);
        fields.text("format", "AdaptiHoundParts"); fields.number("version", 1);
        fields.boolean("complete", success); fields.text("status", success ? "complete" : "incomplete");
        fields.number("parts", static_cast<int64_t>(emitted_parts)); fields.number("records", static_cast<int64_t>(emitted_records));
        fields.number("accepted_records", static_cast<int64_t>(accepted_records));
        fields.text("part_name_prefix", prefix); fields.text("part_name_suffix", no_zip ? ".json" : ".zip"); fields.number("part_name_digits", 6);
        fields.number("part_raw_target", static_cast<int64_t>(raw_target));
        fields.number("single_record_limit", static_cast<int64_t>(row_limit)); fields.number("methods", methods);
        fields.number("parts_crc32", static_cast<int64_t>(~checksum)); fields.text("checksum_format", "crc32(index_le64 || size_le64 || bytes)");
        fields.nullable_text("failure", failure); fields.key("datasets"); AH_TEXT(&manifest, "{");
        ah_fields datasets(manifest);
        for (size_t i = 0; i < 16; ++i) datasets.number(dataset_name(i), static_cast<int64_t>(counts[i]));
        AH_TEXT(&manifest, "}}");
        return !manifest.failed && make_name(0, nullptr, "json") && deliver(name.data, manifest);
    }
public:
    ah_archive_parts(size_t maximum, size_t part_raw_target, int selected, const char *output,
        const ah_profile *profile, const char *domain, sink_fn callback = nullptr, void *context = nullptr,
        size_t single_row_limit = 0)
        : arena(maximum, 512), manifest(8192, 8192), name(2048, 2048), raw(1), formatted(8192, 8192),
          sink(callback), opaque(context), password(ah_zip_password), raw_target(part_raw_target),
          row_limit(single_row_limit > part_raw_target ? single_row_limit : part_raw_target),
          methods(selected), no_zip(ah_no_zip), pretty(ah_pretty_print) {
        // Keep the final status buffer available even when the active part uses
        // the rest of the BOF heap budget.
        manifest.data = ah_alloc(8192);
        if (!manifest.data) { fail("cannot reserve manifest buffer"); return; }
        manifest.capacity = 8192;
        name.data = ah_alloc(2048);
        if (!name.data) { fail("cannot reserve part filename buffer"); return; }
        name.capacity = 2048;
        size_t overhead = 0;
        if (!raw_target || !ah_size_multiply(row_limit / 65536 + (row_limit % 65536 ? 1 : 0), 10, overhead) ||
            !ah_size_add(row_limit, overhead, buffer_limit) || !ah_size_add(buffer_limit, 16384, buffer_limit) ||
            buffer_limit > static_cast<size_t>(INT32_MAX)) { fail("part target exceeds Downloads capacity"); return; }
        raw.limit = buffer_limit;
        char timestamp[16];
        const char *base = output && *output ? output : profile && domain ? ah_default_filename(arena, profile, domain) : nullptr;
        const char *filename = base && ah_output_timestamp(timestamp) ? ah_output_name(arena, base, "zip", timestamp) : nullptr;
        const size_t length = ah_len(filename);
        if (!filename || !length || length > 1024) { fail("cannot create bounded output filename"); return; }
        const size_t stem_length = length >= 4 && ah_eq(filename + length - 4, ".zip") ? length - 4 : length;
        root = arena.copy(filename, stem_length);
        prefix = root ? ah_concat(arena, root, "-part") : nullptr;
        if (!root || !prefix || arena.failed) fail("cannot allocate output names");
    }
    ~ah_archive_parts() { discard(); }
    bool valid() const { return !invalid && !arena.failed && !manifest.failed && !name.failed; }
    bool complete() const { return completed; }
    uint64_t parts() const { return emitted_parts; }
    uint64_t records() const { return emitted_records; }
    uint64_t count(const char *dataset) const {
        const int index = dataset_index(dataset);
        return index >= 0 ? counts[index] : 0;
    }
    const char *failure_reason() const { return failure; }
    bool append(const char *dataset, const ah_buffer &row) {
        if (finalized) return false;
        if (!valid()) return false;
        const int index = dataset_index(dataset);
        if (index < 0 || row.failed || !row.data || row.length > row.capacity || row.length < 2) return fail("invalid complete JSON row");
        size_t first = 0, last = row.length;
        while (first < last && static_cast<unsigned char>(row.data[first]) <= 32) ++first;
        while (last > first && static_cast<unsigned char>(row.data[last - 1]) <= 32) --last;
        if (first == last || row.data[first] != '{' || row.data[last - 1] != '}') return fail("row is not a complete JSON object");
        if (accepted_records >= static_cast<uint64_t>(INT64_MAX)) return fail("record count exceeds JSON capacity");
        if (current >= 0 && current != index && !flush()) return false;
        if (current < 0 && !start(index)) return false;
        size_t length = 0;
        if (!row_size(row, length)) return fail("cannot format complete JSON row");
        if (pending_records && (payload_bytes > raw_target || length > raw_target - payload_bytes)) {
            if (!flush() || !start(index) || !row_size(row, length)) return fail("cannot rotate output part");
        }
        if (length > row_limit) return fail("one JSON object exceeds the single-record memory limit");
        if ((pending_records && !write(",", 1)) || !write(row.data, row.length)) return fail("part buffer allocation or compression failed");
        payload_bytes += length; ++pending_records; ++accepted_records;
        return true;
    }
    bool flush() {
        if (finalized || !valid()) return false;
        if (current < 0) return true;
        if (!pending_records) { discard(); return true; }
        ah_buffer metadata(1024, 1024); AH_TEXT(&metadata, "],\"meta\":{");
        ah_fields fields(metadata); fields.text("type", dataset_name(static_cast<size_t>(current)));
        fields.number("count", static_cast<int64_t>(pending_records)); fields.number("version", 6); fields.number("methods", methods);
        fields.text("collectorversion", "AdaptiHound-BOF"); AH_TEXT(&metadata, "}}");
        if (metadata.failed || !write(metadata.data, metadata.length) || !format.complete() || !drain_format()) return fail("cannot finish JSON part");
        if (!no_zip && (!zip || !zip->end() || !zip->finish())) return fail("cannot finish ZIP part");
        if (!make_name(emitted_parts + 1, nullptr, no_zip ? "json" : "zip")) return fail("cannot format part filename");
        const ah_buffer &body = no_zip ? raw : zip->content();
        const uint32_t next_checksum = part_checksum(body);
        const bool accepted = sink || no_zip ? deliver(name.data, body) : zip->download(name.data);
        if (!accepted) return fail("output sink rejected a completed part");
        checksum = next_checksum; ++emitted_parts; emitted_records += pending_records;
        counts[current] += pending_records;
        discard();
        return true;
    }
    bool finish(bool collection_complete = true) {
        if (finalized) return completed;
        bool success = collection_complete && valid();
        if (success) success = flush();
        if (!success) { if (!failure) fail(collection_complete ? "output did not complete" : "collection did not complete"); discard(); }
        finalized = true;
        if (!emit_manifest(success)) return fail("output sink rejected the final manifest");
        completed = success;
        return completed;
    }
    ah_archive_parts(const ah_archive_parts &) = delete;
    ah_archive_parts &operator=(const ah_archive_parts &) = delete;
};
