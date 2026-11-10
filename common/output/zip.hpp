#pragma once
#include "output_options.hpp"
#include <new>

struct ah_zip_crc_table final {
    uint32_t values[256] = {};
    constexpr ah_zip_crc_table() {
        for (unsigned int i = 0; i < 256; ++i) {
            uint32_t value = i;
            for (unsigned int bit = 0; bit < 8; ++bit) value = (value >> 1) ^ (0xedb88320U & (0U - (value & 1U)));
            values[i] = value;
        }
    }
};
static uint32_t ah_zip_crc_byte(uint32_t crc, unsigned char byte) {
    static constexpr ah_zip_crc_table table;
    return (crc >> 8) ^ table.values[(crc ^ byte) & 255];
}
[[maybe_unused]] static uint32_t ah_zip_crc32(const char *data, size_t size) {
    uint32_t crc = 0xffffffffU;
    for (size_t i = 0; i < size; ++i) crc = ah_zip_crc_byte(crc, static_cast<unsigned char>(data[i]));
    return ~crc;
}
class ah_deflate_bits final {
    ah_buffer &output;
    uint32_t pending = 0;
    unsigned int count = 0;
public:
    explicit ah_deflate_bits(ah_buffer &buffer) : output(buffer) {}
    void put(uint32_t value, unsigned int width) {
        pending |= value << count;
        count += width;
        while (count >= 8) {
            char byte = static_cast<char>(pending);
            ah_append(&output, &byte, 1);
            pending >>= 8; count -= 8;
        }
    }
    static uint32_t reverse(uint32_t value, unsigned int width) {
        uint32_t result = 0;
        for (unsigned int i = 0; i < width; ++i) { result = result << 1 | (value & 1); value >>= 1; }
        return result;
    }
    void literal(unsigned int value) {
        unsigned int code = value < 144 ? value + 0x30 : value < 256 ? value - 144 + 0x190 : value < 280 ? value - 256 : value - 280 + 0xc0;
        unsigned int width = value < 144 ? 8 : value < 256 ? 9 : value < 280 ? 7 : 8;
        put(reverse(code, width), width);
    }
    void finish() { if (count) { char byte = static_cast<char>(pending); ah_append(&output, &byte, 1); } }
};
static unsigned int ah_deflate_hash(const char *data) {
    unsigned int hash = static_cast<unsigned char>(data[0]);
    hash = hash * 251 + static_cast<unsigned char>(data[1]);
    return (hash * 251 + static_cast<unsigned char>(data[2])) & 65535;
}
static bool ah_zip_deflate(const ah_buffer &body, ah_buffer &compressed, bool final = true) {
    uint32_t *dictionary = ah_alloc<uint32_t>((65536 + 32768) * sizeof(uint32_t));
    if (!dictionary) return false;
    uint32_t *previous = dictionary + 65536;
    ah_deflate_bits bits(compressed);
    bits.put(final ? 3 : 2, 3);
    static const unsigned int lengths[] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    static const unsigned char length_bits[] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    static const unsigned int distances[] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    static const unsigned char distance_bits[] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    size_t position = 0;
    while (position < body.length && !compressed.failed) {
        size_t best = 0, distance = 0;
        if (position + 2 < body.length) {
            unsigned int hash = ah_deflate_hash(body.data + position);
            uint32_t candidate = dictionary[hash];
            previous[position & 32767] = candidate;
            dictionary[hash] = static_cast<uint32_t>(position + 1);
            unsigned int attempts = 128;
            size_t maximum = body.length - position < 258 ? body.length - position : 258;
            while (candidate && attempts--) {
                size_t offset = static_cast<size_t>(candidate - 1);
                if (offset >= position || position - offset > 32768) break;
                size_t length = 0;
                while (length < maximum && body.data[offset + length] == body.data[position + length]) ++length;
                if (length > best) { best = length; distance = position - offset; if (best == maximum) break; }
                uint32_t next = previous[offset & 32767];
                if (next >= candidate) break;
                candidate = next;
            }
        }
        if (best >= 3) {
            unsigned int code = 0;
            while (code + 1 < sizeof(lengths) / sizeof(lengths[0]) && lengths[code + 1] <= best) ++code;
            bits.literal(257 + code); bits.put(static_cast<uint32_t>(best - lengths[code]), length_bits[code]);
            code = 0;
            while (code + 1 < sizeof(distances) / sizeof(distances[0]) && distances[code + 1] <= distance) ++code;
            bits.put(ah_deflate_bits::reverse(code, 5), 5); bits.put(static_cast<uint32_t>(distance - distances[code]), distance_bits[code]);
            for (size_t i = 1; i < best && position + i + 2 < body.length; ++i) {
                unsigned int hash = ah_deflate_hash(body.data + position + i);
                previous[(position + i) & 32767] = dictionary[hash]; dictionary[hash] = static_cast<uint32_t>(position + i + 1);
            }
            position += best;
        } else bits.literal(static_cast<unsigned char>(body.data[position++]));
    }
    bits.literal(256);
    if (!final) {

        bits.put(0, 3);
        bits.finish();
        const char empty[] = {0, 0, static_cast<char>(0xff), static_cast<char>(0xff)};
        ah_append(&compressed, empty, sizeof(empty));
    } else bits.finish();
    ah_free(dictionary);
    if (compressed.failed) return false;

    if (compressed.length >= body.length) {
        compressed.length = 0;
        size_t offset = 0;
        do {
            size_t length = body.length - offset < 65535 ? body.length - offset : 65535;
            bool last = offset + length == body.length;
            char header[5] = {static_cast<char>(final && last ? 1 : 0), static_cast<char>(length), static_cast<char>(length >> 8), static_cast<char>(~length), static_cast<char>(~length >> 8)};
            ah_append(&compressed, header, sizeof(header)); if(length)ah_append(&compressed, body.data + offset, length);
            offset += length;
        } while (offset < body.length && !compressed.failed);
    }
    return !compressed.failed;
}
class ah_zip_crypto final {
    uint32_t first = 0x12345678U, second = 0x23456789U, third = 0x34567890U;
    void update(unsigned char value) {
        first = ah_zip_crc_byte(first, value);
        second = (second + (first & 255)) * 134775813U + 1;
        third = ah_zip_crc_byte(third, static_cast<unsigned char>(second >> 24));
    }
public:
    explicit ah_zip_crypto(const char *password) { for (; *password; ++password) update(static_cast<unsigned char>(*password)); }
    unsigned char encrypt(unsigned char value) {
        uint32_t temporary = (third & 65535) | 2;
        unsigned char result = value ^ static_cast<unsigned char>((temporary * (temporary ^ 1)) >> 8);
        update(value); return result;
    }
};
static bool (*ah_archive_sink)(char *, const ah_buffer &) = nullptr;
class ah_zip final {
    struct entry { char *name; uint64_t size, compressed, offset; uint32_t crc; uint16_t flags; bool zip64; entry *next; };
    struct stream final {
        entry &record;
        ah_buffer pending;
        ah_zip_crypto cipher;
        uint32_t crc = 0xffffffffU;
        bool encrypted;
        stream(entry &item, const char *key) : record(item), pending(65536), cipher(key ? key : ""), encrypted(key && *key) {}
    };
    entry *head = nullptr, *tail = nullptr;
    stream *active = nullptr;
    size_t count = 0;
    ah_buffer bytes;
    const char *password;
    uint16_t date = 0x21, time = 0;
    bool finished = false;
    bool fail() { bytes.failed = true; return false; }
    void u16(uint16_t value) { char data[2] = {static_cast<char>(value), static_cast<char>(value >> 8)}; ah_append(&bytes, data, 2); }
    void u32(uint32_t value) { char data[4] = {static_cast<char>(value), static_cast<char>(value >> 8), static_cast<char>(value >> 16), static_cast<char>(value >> 24)}; ah_append(&bytes, data, 4); }
    void u64(uint64_t value) { char data[8]; for (unsigned int i = 0; i < 8; ++i) data[i] = static_cast<char>(value >> (8 * i)); ah_append(&bytes, data, 8); }
    bool stream_bytes(char *data, size_t length) {
        const entry &record = active->record;
        if (length > UINT64_MAX - record.compressed || (!record.zip64 && (record.compressed >= UINT32_MAX || length >= UINT32_MAX - record.compressed))) return fail();
        if (active->encrypted) for (size_t i = 0; i < length; ++i) data[i] = static_cast<char>(active->cipher.encrypt(static_cast<unsigned char>(data[i])));
        ah_append(&bytes, data, length);
        if (bytes.failed) return false;
        active->record.compressed += length;
        return true;
    }
    bool flush_stream() {
        if (!active->pending.length) return true;

        ah_buffer compressed(65536 + 65536 / 8 + 32);
        if (!ah_zip_deflate(active->pending, compressed, false) || !stream_bytes(compressed.data, compressed.length)) return fail();
        active->pending.length = 0;
        return true;
    }
    void release_stream() {
        if (!active) return;
        active->~stream(); ah_free(active); active = nullptr;
    }
public:
    explicit ah_zip(size_t maximum, const char *zip_password = nullptr) : bytes(maximum), password(zip_password) {
        SYSTEMTIME now = {};
        if (ah_output_system_time(now) && now.wYear >= 1980 && now.wYear <= 2107) {
            date = static_cast<uint16_t>((now.wYear - 1980) << 9 | now.wMonth << 5 | now.wDay);
            time = static_cast<uint16_t>(now.wHour << 11 | now.wMinute << 5 | now.wSecond / 2);
        }
    }
    ~ah_zip() { release_stream(); while (head) { entry *next=head->next; ah_free(head->name); ah_free(head); head=next; } }
    ah_zip(const ah_zip &) = delete;
    ah_zip &operator=(const ah_zip &) = delete;
    bool begin(const char *name, bool zip64 = true) {
        size_t name_length = ah_len(name);
        if (finished || active || bytes.failed || count == SIZE_MAX || !name_length || name_length > 65535) return fail();
        entry *record = ah_alloc<entry>(sizeof(entry));
        if (!record) return fail();
        record->name = ah_alloc(name_length + 1);
        if (!record->name) { ah_free(record); return fail(); }
        for (size_t i = 0; i <= name_length; ++i) record->name[i] = name[i];
        stream *context = ah_alloc<stream>(sizeof(stream));
        if (!context) { ah_free(record->name); ah_free(record); return fail(); }
        new(context)stream(*record, password);
        active = context;
        record->offset = bytes.length;
        record->zip64 = zip64;
        record->flags = static_cast<uint16_t>(0x0808 | (context->encrypted ? 1 : 0));
        if (tail) tail->next = record; else head = record;
        tail = record; ++count;

        u32(0x04034b50); u16(zip64 ? 45 : 20); u16(record->flags); u16(8); u16(time); u16(date);
        u32(0); u32(zip64 ? UINT32_MAX : 0); u32(zip64 ? UINT32_MAX : 0); u16(static_cast<uint16_t>(name_length)); u16(zip64 ? 20 : 0);
        ah_append(&bytes, record->name, name_length);
        if (zip64) { u16(0x0001); u16(16); u64(0); u64(0); }
        if (context->encrypted) {
            unsigned char header[12];
            if (!ah_output_random(header, sizeof(header) - 1)) return fail();

            header[11] = static_cast<unsigned char>(time >> 8);
            if (!stream_bytes(reinterpret_cast<char *>(header), sizeof(header))) return false;
        }
        return !bytes.failed;
    }
    bool write(const char *data, size_t length) {
        if (!active || bytes.failed || (!data && length) || length > UINT64_MAX - active->record.size) return fail();
        if (!active->record.zip64 && (active->record.size >= UINT32_MAX || length >= UINT32_MAX - active->record.size)) return fail();
        active->record.size += length;
        while (length) {
            size_t available = 65536 - active->pending.length;
            size_t take = length < available ? length : available;
            ah_append(&active->pending, data, take);
            if (active->pending.failed) return fail();
            for (size_t i = 0; i < take; ++i) active->crc = ah_zip_crc_byte(active->crc, static_cast<unsigned char>(data[i]));
            data += take; length -= take;
            if (active->pending.length == 65536 && !flush_stream()) return false;
        }
        return true;
    }
    bool end() {
        if (!active) return fail();
        bool success = !bytes.failed && flush_stream();
        if (success) {
            char final_block[] = {1, 0, 0, static_cast<char>(0xff), static_cast<char>(0xff)};
            success = stream_bytes(final_block, sizeof(final_block));
        }
        if (success) {
            entry &record = active->record;
            record.crc = ~active->crc;
            u32(0x08074b50); u32(record.crc);
            if (record.zip64) { u64(record.compressed); u64(record.size); }
            else { u32(static_cast<uint32_t>(record.compressed)); u32(static_cast<uint32_t>(record.size)); }
            success = !bytes.failed;
        }
        release_stream();
        return success ? true : fail();
    }
    bool add(const char *name, const ah_buffer &body) {
        if (active) return fail();
        if (finished || bytes.failed || body.failed || body.length > body.capacity || (!body.data && body.length) || &body == &bytes) return false;

        const bool zip64 = body.length >= UINT32_MAX || body.length + ((body.length + 65535) / 65536) * 10 + 17 >= UINT32_MAX;
        const bool success = begin(name, zip64) && write(body.data, body.length) && end();

        if (!success) release_stream();
        return success;
    }

    bool add_atomic(const char *name, const ah_buffer &body) {
        if (active || finished || bytes.failed) return false;
        const size_t length = bytes.length;
        const size_t previous_count = count;
        entry *previous_head = head, *previous_tail = tail;
        if (add(name, body)) return true;
        entry *discard = previous_tail ? previous_tail->next : head;
        if (previous_tail) previous_tail->next = nullptr;
        while (discard) { entry *next = discard->next; ah_free(discard->name); ah_free(discard); discard = next; }
        head = previous_head; tail = previous_tail; count = previous_count;
        bytes.length = length; bytes.failed = false;
        return false;
    }
    bool finish(bool allow_empty = false) {
        if (active) return fail();
        if (finished) return !bytes.failed && (count != 0 || allow_empty);
        if ((!count && !allow_empty) || bytes.failed) return false;
        finished = true;
        const uint64_t start = bytes.length;
        bool zip64 = count >= UINT16_MAX;
        for (const entry *item=head;item;item=item->next) {
            const entry &record=*item;
            const bool large_sizes = record.zip64, large_offset = record.offset >= UINT32_MAX;
            const uint16_t extra = static_cast<uint16_t>((large_sizes ? 16 : 0) + (large_offset ? 8 : 0));
            const uint16_t version = extra ? 45 : 20;
            if (extra) zip64 = true;
            u32(0x02014b50); u16(version); u16(version); u16(record.flags); u16(8); u16(time); u16(date);
            u32(record.crc); u32(large_sizes ? UINT32_MAX : static_cast<uint32_t>(record.compressed)); u32(large_sizes ? UINT32_MAX : static_cast<uint32_t>(record.size)); u16(static_cast<uint16_t>(ah_len(record.name)));
            u16(extra ? extra + 4 : 0); u16(0); u16(0); u16(0); u32(0); u32(large_offset ? UINT32_MAX : static_cast<uint32_t>(record.offset));
            ah_append(&bytes, record.name, ah_len(record.name));
            if (extra) { u16(0x0001); u16(extra); if (large_sizes) { u64(record.size); u64(record.compressed); } if (large_offset) u64(record.offset); }
            if (bytes.failed) return false;
        }
        const uint64_t central_size = bytes.length - start;
        if (start >= UINT32_MAX || central_size >= UINT32_MAX) zip64 = true;
        if (zip64) {
            const uint64_t locator = bytes.length;
            u32(0x06064b50); u64(44); u16(45); u16(45); u32(0); u32(0); u64(count); u64(count); u64(central_size); u64(start);
            u32(0x07064b50); u32(0); u64(locator); u32(1);
        }
        const uint16_t short_count = count >= UINT16_MAX ? UINT16_MAX : static_cast<uint16_t>(count);
        u32(0x06054b50); u16(0); u16(0); u16(short_count); u16(short_count); u32(central_size >= UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(central_size)); u32(start >= UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(start)); u16(0);
        return !bytes.failed;
    }
    const ah_buffer &content() const { return bytes; }
    bool download(char *filename, bool allow_empty = false) {
        if (!filename || !*filename) return false;
        if (!ah_archive_sink && bytes.length > INT32_MAX) { BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: ZIP exceeds AxDownloadMemory's signed 2 GiB transfer limit"); return false; }
        if(!finish(allow_empty))return false;
        if(ah_archive_sink)return ah_archive_sink(filename,bytes);
        if (bytes.length > INT32_MAX) { BeaconPrintf(CALLBACK_ERROR, "AdaptiHound: ZIP exceeds AxDownloadMemory's signed 2 GiB transfer limit"); return false; }
        AxDownloadMemory(filename, bytes.data, static_cast<int>(bytes.length));
        if (ah_telemetry_enabled)
            BeaconPrintf(CALLBACK_OUTPUT, "AdaptiHound: archive prepared for Downloads: %s (%llu bytes, %llu entries)", filename, static_cast<unsigned long long>(bytes.length), static_cast<unsigned long long>(count));
        return true;
    }
};
