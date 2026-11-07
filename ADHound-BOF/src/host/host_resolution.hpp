#pragma once

static const char *ah_host_account_sid(ah_graph &g, const char *account, const char *domain) {
    const char *directory_id = nullptr;
    if (ah_resolve_directory_account_sid(g, account, domain, &directory_id)) return directory_id;
    wchar_t *qualified = ah_wide(ah_concat(g.arena, domain, "\\", account));
    unsigned char sid[256] = {}; wchar_t resolved_domain[256] = {};
    DWORD size = sizeof(sid), domain_size = 256; SID_NAME_USE use = SidTypeUnknown;
    bool found = qualified && ADVAPI32$LookupAccountNameW(nullptr, qualified, sid, &size, resolved_domain, &domain_size, &use);
    ah_free(qualified);
    return found && (use == SidTypeUser || use == SidTypeComputer) ? ah_sid_from_psid(g.arena, sid) : nullptr;
}
static const char *ah_host_workstation_sid(ah_graph &g, const char *host) {
    if (!ah_tcp_open(host, 445)) return nullptr;
    ah_native_library netapi(L"netapi32.dll");
    auto query = netapi.find<decltype(&NetWkstaGetInfo)>("NetWkstaGetInfo");
    if (!query) return nullptr;
    wchar_t *wide = ah_wide(host); WKSTA_INFO_100 *information = nullptr;
    NET_API_STATUS status = wide ? query(wide, 100, reinterpret_cast<LPBYTE *>(&information)) : ERROR_NOT_ENOUGH_MEMORY;
    ah_free(wide);
    const char *result = nullptr;
    if (status == NERR_Success && information && information->wki100_computername && *information->wki100_computername) {
        const char *name = ah_concat(g.arena, g.arena.utf8(information->wki100_computername), "$");
        const char *domain = information->wki100_langroup && *information->wki100_langroup ? g.arena.utf8(information->wki100_langroup) : g.domain;
        result = ah_host_account_sid(g, name, domain);
    }
    if (information) NETAPI32$NetApiBufferFree(information);
    return result;
}
static const char *ah_host_netbios_sid(ah_graph &g, const char *host) {
    WSADATA data = {};
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &data)) return nullptr;
    ADDRINFOA hints = {}, *addresses = nullptr;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM; hints.ai_protocol = IPPROTO_UDP;
    const char *name = host; bool qualified = false;
    for (const char *p = host; *p; ++p) if (*p == '.') qualified = true;
    if (!qualified) name = ah_concat(g.arena, host, ".", g.domain);
    const char *result = nullptr;
    if (!WS2_32$getaddrinfo(name, "137", &hints, &addresses)) {
        static const unsigned char request[] = {
            0x80,0x94,0,0,0,1,0,0,0,0,0,0,0x20,0x43,0x4b,0x41,
            0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
            0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0,0,0x21,0,1
        };
        for (ADDRINFOA *address = addresses; address && !result; address = address->ai_next) {
            SOCKET socket = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (socket == INVALID_SOCKET) continue;
            DWORD timeout = 1000;
            WS2_32$setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
            WS2_32$setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeout), sizeof(timeout));
            unsigned char response[1024] = {};
            if (!WS2_32$connect(socket, address->ai_addr, static_cast<int>(address->ai_addrlen)) && WS2_32$send(socket, reinterpret_cast<const char *>(request), sizeof(request), 0) == static_cast<int>(sizeof(request))) {
                int length = WS2_32$recv(socket, reinterpret_cast<char *>(response), sizeof(response), 0);
                if (length >= 90 && response[0] == request[0] && response[1] == request[1]) {
                    char netbios[17] = {}; for (unsigned int i = 0; i < 16; ++i) netbios[i] = static_cast<char>(response[57 + i]);
                    size_t n = 16; while (n && (netbios[n - 1] == ' ' || netbios[n - 1] == 0)) --n;
                    netbios[n] = 0;
                    if (n) result = ah_host_account_sid(g, ah_concat(g.arena, netbios, "$"), g.domain);
                }
            }
            WS2_32$closesocket(socket);
        }
        WS2_32$freeaddrinfo(addresses);
    }
    WS2_32$WSACleanup(); return result;
}
