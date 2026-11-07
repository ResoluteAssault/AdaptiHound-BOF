#ifndef ADAPTIHOUND_COLLECTOR_H
#define ADAPTIHOUND_COLLECTOR_H
#define SECURITY_WIN32
#include <winsock2.h>
#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdint.h>
#include "beacon.h"
extern "C" {
#include "adaptix.h"
}

typedef struct {
    const wchar_t *type;
    const wchar_t *prefix;
    const wchar_t *filter;
    ULONG scope;
    int optional;
} ah_query;

typedef struct {
    const char *backend;
    const ah_query *queries;
    unsigned int query_count;
    const wchar_t *const *attributes;
    int security_descriptors;
} ah_profile;

static void ah_collect(char *args, int length, const ah_profile *profile);
#endif
