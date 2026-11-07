#pragma once

static const char *ah_status_number(ah_arena &arena, ULONG status, bool signed_value = false) {
    char text[16]; size_t length = 0;
    const bool negative = signed_value && (status & 0x80000000UL);
    ULONG value = negative ? 0UL - status : status;
    do { text[length++] = static_cast<char>('0' + value % 10); value /= 10; } while (value);
    char result[16]; size_t offset = 0;
    if (negative) result[offset++] = '-';
    while (length) result[offset++] = text[--length];
    result[offset] = 0; return arena.copy(result);
}

static const char *ah_ntstatus_name(ah_arena &arena, ULONG status) {
    switch (status) {
    case 0: return "StatusSuccess";
    case 0x105: return "StatusMoreEntries";
    case 0x107: return "StatusSomeMapped";
    case 0xc0000008UL: return "StatusInvalidHandle";
    case 0xc000000dUL: return "StatusInvalidParameter";
    case 0xc0000022UL: return "StatusAccessDenied";
    case 0xc0000024UL: return "StatusObjectTypeMismatch";
    case 0xc00000dfUL: return "StatusNoSuchDomain";
    case 0xc0020017UL: return "StatusRpcServerUnavailable";
    case 0xc0000151UL: return "StatusNoSuchAlias";
    case 0x8000001aUL: return "StatusNoMoreEntries";
    default: return ah_status_number(arena, status, true);
    }
}

static const char *ah_netapi_status_name(ah_arena &arena, ULONG status) {
    switch (status) {
    case 0: return "Success";
    case 2351: return "InvalidComputer";
    case 2226: return "NotPrimary";
    case 2234: return "SpeGroupOp";
    case 2452: return "LastAdmin";
    case 2203: return "BadPassword";
    case 2245: return "PasswordTooShort";
    case 2221: return "UserNotFound";
    case 5: return "ErrorAccessDenied";
    case 8: return "ErrorNotEnoughMemory";
    case 87: return "ErrorInvalidParameter";
    case 123: return "ErrorInvalidName";
    case 124: return "ErrorInvalidLevel";
    case 234: return "ErrorMoreData";
    case 1219: return "ErrorSessionCredentialConflict";
    case 0x800706baUL: return "RpcSServerUnavailable";
    case 0x8001011cUL: return "RpcERemoteDisabled";
    default: return ah_status_number(arena, status);
    }
}

static const char *ah_registry_status_reason(ah_arena &arena, const char *operation, LONG status) {
    if (status == ERROR_ACCESS_DENIED) return "User does not have the proper permissions to perform this operation";
    if (status == ERROR_BAD_NETPATH || status == ERROR_BAD_NET_NAME || status == ERROR_NETNAME_DELETED ||
        status == ERROR_NETWORK_UNREACHABLE || status == RPC_S_SERVER_UNAVAILABLE)
        return "Target machine was not found or not connectable";
    return ah_win32_failure(arena, operation, static_cast<ULONG>(status));
}
