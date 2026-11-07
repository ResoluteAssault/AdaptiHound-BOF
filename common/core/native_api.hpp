#pragma once

struct ah_native_unicode { USHORT length, maximum; wchar_t *buffer; };
struct ah_native_ansi { USHORT length, maximum; char *buffer; };
extern "C" {
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$LdrLoadDll(wchar_t *, ULONG *, ah_native_unicode *, void **);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$LdrGetProcedureAddress(void *, ah_native_ansi *, ULONG, void **);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$LdrUnloadDll(void *);
}
class ah_native_library final {
    void *module = nullptr;
public:
    explicit ah_native_library(const wchar_t *name) {
        size_t size = ah_wlen(name) * sizeof(wchar_t);
        if (size > 65532) return;
        ah_native_unicode value = {static_cast<USHORT>(size), static_cast<USHORT>(size + sizeof(wchar_t)), const_cast<wchar_t *>(name)};
        if (NTDLL$LdrLoadDll(nullptr, nullptr, &value, &module) < 0) module = nullptr;
    }
    ~ah_native_library() { if (module) NTDLL$LdrUnloadDll(module); }
    ah_native_library(const ah_native_library &) = delete;
    ah_native_library &operator=(const ah_native_library &) = delete;
    template <typename Function> Function find(const char *name) const {
        size_t size = ah_len(name); void *result = nullptr;
        if (!module || size > 65534) return nullptr;
        ah_native_ansi value = {static_cast<USHORT>(size), static_cast<USHORT>(size + 1), const_cast<char *>(name)};
        if (NTDLL$LdrGetProcedureAddress(module, &value, 0, &result) < 0) return nullptr;
        return reinterpret_cast<Function>(result);
    }
};
