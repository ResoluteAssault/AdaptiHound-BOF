#pragma once
#include "zip.hpp"
static char *ah_default_filename(ah_arena &arena, const ah_profile *profile, const char *domain) {
    char *lower = arena.copy(domain);
    if (!lower) return nullptr;
    for (char *p = lower; *p; ++p) *p = ah_lower(*p);
    char *prefix = ah_concat(arena, "adaptihound-", profile->backend, "-");
    return prefix ? ah_concat(arena, prefix, lower, ".zip") : nullptr;
}

static bool ah_write_dataset(ah_arena &arena,ah_zip &zip,ah_buffer &json,const char *base,const char *timestamp) {
    if(ah_pretty_print&&!ah_pretty_json(json))return false;
    char *name=ah_output_name(arena,base,"json",timestamp);
    if(!name||json.failed||json.length>0x7fffffffU)return false;
    if(ah_no_zip)AxDownloadMemory(name,json.data,static_cast<int>(json.length));
    else if(!zip.add(name,json))return false;
    return !arena.failed;
}
