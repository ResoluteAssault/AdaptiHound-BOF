#pragma once
#include "../cache/cache.hpp"

static bool ah_random_bytes(unsigned char *bytes, size_t length) {
    if (length > UINT32_MAX) return false;
    ah_native_library library(L"bcrypt.dll");
    using generate_fn = LONG (WINAPI *)(void *, unsigned char *, ULONG, ULONG);
    auto generate = library.find<generate_fn>("BCryptGenRandom");
    return generate && generate(nullptr, bytes, static_cast<ULONG>(length), 2) >= 0;
}

static void ah_computer_delay() {
    if (ah_throttle <= 0) return;
    uint64_t delay = static_cast<unsigned int>(ah_throttle);
    if (ah_jitter) {

        uint32_t percent = static_cast<uint32_t>(ah_jitter * (ah_throttle / 100));
        uint32_t random = 0;
        if (percent && ah_random_bytes(reinterpret_cast<unsigned char *>(&random), sizeof(random)))
            delay = delay - percent + random % (2ULL * percent);
    }
    while (delay) { DWORD slice = static_cast<DWORD>(delay > 1000 ? 1000 : delay); KERNEL32$Sleep(slice); delay -= slice; }
}

struct ah_wide_secret final {
    wchar_t *value;
    explicit ah_wide_secret(const char *text) : value(ah_wide(text)) {}
    ~ah_wide_secret() { if (value) { volatile wchar_t *p = value; size_t n = ah_wlen(value); while (n--) *p++ = 0; ah_free(value); } }
    ah_wide_secret(const ah_wide_secret &) = delete;
    ah_wide_secret &operator=(const ah_wide_secret &) = delete;
};

static bool ah_register_directory_handle(LDAP *,const wchar_t *,const ah_options &,bool);
static void ah_note_directory_domain(LDAP *,const wchar_t *);
static LDAP *ah_open_domain_directory(const wchar_t *,const ah_options &,bool,ULONG,ULONG &);

static LDAP *ah_open_directory(const wchar_t *server, const ah_options &options, bool global_catalog, ULONG timeout_seconds, ULONG &status) {
    ah_wide_secret bind_dn(options.user), simple_password(options.password);
    ah_wide_secret username(options.ldap_username), password(options.ldap_password);
    if (!bind_dn.value || !simple_password.value || !username.value || !password.value) { status = LDAP_NO_MEMORY; return nullptr; }
    SEC_WINNT_AUTH_IDENTITY_EXW identity = {};
    identity.Version = SEC_WINNT_AUTH_IDENTITY_VERSION; identity.Length = sizeof(identity); identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    if (options.kerberos) { identity.PackageList = reinterpret_cast<unsigned short *>(const_cast<wchar_t *>(L"!ntlm")); identity.PackageListLength = 5; }
    if (*username.value) {
        wchar_t *account = username.value, *separator = nullptr;
        for (wchar_t *p = account; *p; ++p) if (*p == '\\') { separator = p; break; }
        if (separator) { *separator = 0; identity.Domain = reinterpret_cast<unsigned short *>(account); identity.DomainLength = static_cast<ULONG>(ah_wlen(account)); account = separator + 1; }
        identity.User = reinterpret_cast<unsigned short *>(account); identity.UserLength = static_cast<ULONG>(ah_wlen(account));
        identity.Password = reinterpret_cast<unsigned short *>(password.value); identity.PasswordLength = static_cast<ULONG>(ah_wlen(password.value));
    }
    const bool force_secure = options.tls || *bind_dn.value;
    for (int attempt = 0; attempt < (force_secure ? 1 : 2); ++attempt) {
        const bool secure = attempt == 0;
        ULONG port = global_catalog ? (secure ? 3269 : 3268) : secure ?
            (options.ssl_port ? static_cast<ULONG>(options.ssl_port) : *bind_dn.value && options.port ? static_cast<ULONG>(options.port) : 636) :
            (options.port ? static_cast<ULONG>(options.port) : 389);
        LDAP *ld = ah_bind_ldap(server, port, secure, !secure && !(options.runtime_flags & 2) ? 1 : 0,
            (options.runtime_flags & 4) != 0, *bind_dn.value ? bind_dn.value : nullptr,
            *bind_dn.value ? simple_password.value : (*username.value || options.kerberos ? reinterpret_cast<wchar_t *>(&identity) : nullptr),
            *bind_dn.value ? LDAP_AUTH_SIMPLE : LDAP_AUTH_NEGOTIATE, timeout_seconds, status);
        if (!ld) {
            if (status == LDAP_INVALID_CREDENTIALS || status == LDAP_INAPPROPRIATE_AUTH) break;
            continue;
        }
        if (!status) {
            if(ah_register_directory_handle(ld,server,options,global_catalog))return ld;
            status=LDAP_NO_MEMORY;
        }
        WLDAP32$ldap_unbind(ld);
        if (status == LDAP_INVALID_CREDENTIALS || status == LDAP_INAPPROPRIATE_AUTH) break;
    }
    return nullptr;
}

struct ah_gc_cache_entry { const char *name; ah_session_info *matches; ah_gc_cache_entry *next; };
struct ah_ldap_handle_record {
    LDAP *handle,*replacement;
    wchar_t *server,*domain;
    bool global_catalog,closed;
    ah_ldap_handle_record *next;
};
struct ah_directory_runtime final {
    const ah_options &options;
    ah_directory_runtime *previous;
    LDAP *gc = nullptr;
    LDAP *primary = nullptr;
    const wchar_t *primary_server = nullptr;
    ah_gc_cache_entry *cache = nullptr;
    ah_arena cache_storage;
    ah_ldap_handle_record *handles=nullptr;
    wchar_t *gc_base=nullptr;
    CRITICAL_SECTION lock={};
    bool lock_initialized=false,published,owns_primary=false;
    explicit ah_directory_runtime(const ah_options &value,bool activate=true);
    ~ah_directory_runtime();
};
static ah_directory_runtime *ah_current_directory_runtime = nullptr;
ah_directory_runtime::ah_directory_runtime(const ah_options &value,bool activate) : options(value), previous(activate?ah_current_directory_runtime:nullptr),cache_storage(0,4096),published(activate) {
    lock_initialized=KERNEL32$InitializeCriticalSectionAndSpinCount(&lock,4000)!=0;
    if(published)ah_current_directory_runtime=this;
}
ah_directory_runtime::~ah_directory_runtime() {
    if(gc)ah_close_directory(gc);
    if(primary&&owns_primary)ah_close_directory(primary);
    ah_free(gc_base);
    while(handles){
        auto *record=handles;handles=record->next;
        if(!record->closed)WLDAP32$ldap_unbind(record->handle);
        ah_free(record->server);ah_free(record->domain);ah_free(record);
    }
    if(lock_initialized)KERNEL32$DeleteCriticalSection(&lock);
    if(published)ah_current_directory_runtime=previous;
}
static ah_directory_runtime *ah_runtime_for(ah_graph &graph) {
    return graph.directory_runtime?static_cast<ah_directory_runtime*>(graph.directory_runtime):ah_current_directory_runtime;
}
struct ah_directory_guard final {
    ah_directory_runtime *runtime;
    explicit ah_directory_guard(ah_graph &graph):runtime(ah_runtime_for(graph)){if(runtime&&runtime->lock_initialized)KERNEL32$EnterCriticalSection(&runtime->lock);}

    ah_directory_guard():runtime(ah_current_directory_runtime){if(runtime&&runtime->lock_initialized)KERNEL32$EnterCriticalSection(&runtime->lock);}
    ~ah_directory_guard(){if(runtime&&runtime->lock_initialized)KERNEL32$LeaveCriticalSection(&runtime->lock);}
    ah_directory_guard(const ah_directory_guard&)=delete;
    ah_directory_guard &operator=(const ah_directory_guard&)=delete;
};
static wchar_t *ah_directory_wide_copy(const wchar_t *value) {
    if(!value)return nullptr;
    const size_t length=ah_wlen(value);
    if(length>=SIZE_MAX/sizeof(wchar_t))return nullptr;
    auto *copy=ah_alloc<wchar_t>((length+1)*sizeof(wchar_t));
    if(copy)for(size_t i=0;i<=length;++i)copy[i]=value[i];
    return copy;
}
static ah_ldap_handle_record *ah_directory_record(LDAP *handle) {
    auto *runtime=ah_current_directory_runtime;
    for(auto *record=runtime?runtime->handles:nullptr;record;record=record->next)
        if(record->handle==handle)return record;
    return nullptr;
}
static bool ah_register_directory_handle(LDAP *handle,const wchar_t *server,const ah_options &options,bool global_catalog) {
    auto *runtime=ah_current_directory_runtime;
    if(!runtime)return true;
    auto *record=ah_alloc<ah_ldap_handle_record>(sizeof(ah_ldap_handle_record));
    auto *host=ah_directory_wide_copy(server);
    auto *domain=ah_wide(options.domain?options.domain:"");
    if(!record||!host||!domain){ah_free(record);ah_free(host);ah_free(domain);return false;}
    *record={handle,nullptr,host,domain,global_catalog,false,nullptr};
    ah_directory_guard guard;
    record->next=runtime->handles;runtime->handles=record;
    return true;
}
static void ah_note_directory_domain(LDAP *handle,const wchar_t *domain) {
    wchar_t *copy=ah_directory_wide_copy(domain);
    if(!copy)return;
    ah_directory_guard guard;
    handle=ah_ldap_current(handle);
    if(auto *record=ah_directory_record(handle)){ah_free(record->domain);record->domain=copy;}
    else ah_free(copy);
}
static void ah_note_directory_server(LDAP *handle,const wchar_t *server) {
    wchar_t *copy=ah_directory_wide_copy(server);
    if(!copy)return;
    ah_directory_guard guard;
    handle=ah_ldap_current(handle);
    if(auto *record=ah_directory_record(handle)){ah_free(record->server);record->server=copy;}
    else ah_free(copy);
}
static LDAP *ah_ldap_current(LDAP *handle) {
    ah_directory_guard guard;
    for(auto *record=ah_directory_record(handle);record&&record->replacement;record=ah_directory_record(handle))handle=record->replacement;
    return handle;
}
static void ah_close_directory(LDAP *handle) {
    if(!handle)return;
    {
        ah_directory_guard guard;
        for(auto *record=ah_directory_record(handle);record&&record->replacement;record=ah_directory_record(handle))handle=record->replacement;
        if(auto *record=ah_directory_record(handle)){
            if(record->closed)return;
            record->closed=true;
        }
    }
    WLDAP32$ldap_unbind(handle);
}
static bool ah_ldap_recover(LDAP *&handle,bool same_server) {
    auto *runtime=ah_current_directory_runtime;
    if(!runtime)return false;
    ah_ldap_handle_record *record=nullptr;
    {ah_directory_guard guard;record=ah_directory_record(handle);}
    if(!record)return false;
    ULONG status=LDAP_SERVER_DOWN;
    LDAP *replacement=same_server||!record->domain||!*record->domain?
        ah_open_directory(record->server,runtime->options,record->global_catalog,30,status):
        ah_open_domain_directory(record->domain,runtime->options,record->global_catalog,30,status);
    if(!replacement)return false;
    if(replacement==handle){ah_close_directory(replacement);return false;}
    if(record->domain&&*record->domain)ah_note_directory_domain(replacement,record->domain);
    ah_directory_guard guard;
    record->replacement=replacement;
    if(runtime->primary==handle)runtime->primary=replacement;
    if(runtime->gc==handle)runtime->gc=replacement;
    handle=replacement;
    return true;
}
static LDAP *ah_open_domain_directory(const wchar_t *domain,const ah_options &options,bool global_catalog,ULONG timeout,ULONG &status) {
    if(options.server&&*options.server){
        wchar_t *server=ah_wide(options.server);
        if(!server){status=LDAP_NO_MEMORY;return nullptr;}
        LDAP *handle=ah_open_directory(server,options,global_catalog,timeout,status);
        if(handle&&domain)ah_note_directory_domain(handle,domain);
        ah_free(server);return handle;
    }
    LDAP *handle=nullptr;bool terminal=false;
    auto attempt=[&](const wchar_t *server){
        if(terminal||!server||!*server)return false;
        if(server[0]==L'\\'&&server[1]==L'\\')server+=2;
        handle=ah_open_directory(server,options,global_catalog,timeout,status);
        terminal=status==LDAP_INVALID_CREDENTIALS||status==LDAP_INAPPROPRIATE_AUTH||status==LDAP_NO_MEMORY;
        if(handle&&domain)ah_note_directory_domain(handle,domain);
        return handle!=nullptr;
    };
    if(attempt(domain)||terminal)return handle;
    PDOMAIN_CONTROLLER_INFOW dc=nullptr;
    const ULONG flags=DS_FORCE_REDISCOVERY|DS_RETURN_DNS_NAME|DS_DIRECTORY_SERVICE_REQUIRED;
    if(NETAPI32$DsGetDcNameW(nullptr,domain,nullptr,nullptr,flags,&dc)==ERROR_SUCCESS&&dc){
        if(dc->DomainName&&(!domain||!ah_weq(dc->DomainName,domain)))attempt(dc->DomainName);
        if(!handle&&!terminal)attempt(dc->DomainControllerName);
        NETAPI32$NetApiBufferFree(dc);dc=nullptr;
    }
    if(handle||terminal)return handle;
    if(NETAPI32$DsGetDcNameW(nullptr,domain,nullptr,nullptr,flags|DS_PDC_REQUIRED,&dc)==ERROR_SUCCESS&&dc){
        attempt(dc->DomainControllerName);NETAPI32$NetApiBufferFree(dc);dc=nullptr;
    }
    if(handle||terminal)return handle;
    struct dc_enumeration final {
        HANDLE value=nullptr;
        ~dc_enumeration(){if(value)NETAPI32$DsGetDcCloseW(value);}
    } enumeration;
    if(NETAPI32$DsGetDcOpenW(domain,0,nullptr,nullptr,nullptr,DS_DIRECTORY_SERVICE_REQUIRED,&enumeration.value)!=ERROR_SUCCESS)return nullptr;
    for(;;){
        wchar_t *server=nullptr;
        const DWORD found=NETAPI32$DsGetDcNextW(enumeration.value,nullptr,nullptr,&server);
        if(found==ERROR_FILEMARK_DETECTED){if(server)NETAPI32$NetApiBufferFree(server);continue;}
        if(found!=ERROR_SUCCESS){if(server)NETAPI32$NetApiBufferFree(server);break;}
        attempt(server);if(server)NETAPI32$NetApiBufferFree(server);
        if(handle||terminal)break;
    }
    return handle;
}
static bool ah_parallel_directory_ready(){return ah_current_directory_runtime&&ah_current_directory_runtime->lock_initialized;}
static bool ah_worker_directory_runtime_required(){return ah_current_directory_runtime!=nullptr;}
static void *ah_create_worker_directory_runtime(){
    auto *source=ah_current_directory_runtime;
    if(!source)return nullptr;
    auto *runtime=ah_alloc<ah_directory_runtime>(sizeof(ah_directory_runtime));
    if(!runtime)return nullptr;
    new(runtime)ah_directory_runtime(source->options,false);
    if(!runtime->lock_initialized){runtime->~ah_directory_runtime();ah_free(runtime);return nullptr;}
    runtime->primary_server=source->primary_server;
    return runtime;
}
static void ah_destroy_worker_directory_runtime(void *context){
    if(!context)return;
    auto *runtime=static_cast<ah_directory_runtime*>(context);
    runtime->~ah_directory_runtime();ah_free(runtime);
}
static LDAP *ah_runtime_primary(ah_directory_runtime *runtime){
    if(!runtime||runtime->primary||runtime->published)return runtime?runtime->primary:nullptr;
    wchar_t *override_host=nullptr;
    const wchar_t *host=runtime->primary_server;
    if(!host&&runtime->options.server&&*runtime->options.server)host=override_host=ah_wide(runtime->options.server);
    ULONG status=LDAP_LOCAL_ERROR;
    if(host){
        runtime->primary=ah_open_directory(host,runtime->options,false,30,status);runtime->owns_primary=runtime->primary!=nullptr;
        auto *root=ah_current_directory_runtime;
        if(runtime->primary&&root){ah_directory_guard guard;if(auto *record=ah_directory_record(root->primary))if(record->domain&&*record->domain)ah_note_directory_domain(runtime->primary,record->domain);}
    }
    ah_free(override_host);
    return runtime->primary;
}

static LDAP *ah_global_catalog(ah_graph &graph) {
    ah_directory_guard guard(graph);
    auto *runtime = ah_runtime_for(graph);
    if (!runtime) return nullptr;
    if(!runtime->gc){
        wchar_t *domain=ah_wide(graph.domain);
        ULONG status=LDAP_LOCAL_ERROR;
        if(domain)runtime->gc=ah_open_domain_directory(domain,runtime->options,true,10,status);
        ah_free(domain);
    }
    if(runtime->gc&&!runtime->gc_base){
        runtime->gc_base=ah_root(runtime->gc,L"defaultNamingContext");
        if(!runtime->gc_base){
            char *base=ah_domain_base(graph.domain);
            runtime->gc_base=base?ah_wide(base):nullptr;ah_free(base);
        }
    }
    runtime->gc=ah_ldap_current(runtime->gc);
    return runtime->gc;
}

static char *ah_filter_escape(ah_arena &arena, const char *value) {
    ah_buffer result(1024 * 1024); static const char hex[] = "0123456789abcdef";
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value); *p; ++p) {
        if (*p == '*' || *p == '(' || *p == ')' || *p == '\\' || *p < 32 || *p >= 128) {
            char escaped[] = {'\\', hex[*p >> 4], hex[*p & 15]}; ah_append(&result, escaped, sizeof(escaped));
        } else ah_append(&result, reinterpret_cast<const char *>(p), 1);
    }
    AH_TEXT(&result, "\0"); return result.failed ? nullptr : arena.copy(result.data);
}

template <typename Consumer>
static bool ah_gc_search(ah_graph &graph, const char *filter, Consumer consume) {
    ah_directory_guard guard(graph);
    LDAP *gc = ah_global_catalog(graph); wchar_t *wide = filter ? ah_wide(filter) : nullptr;
    auto *runtime=ah_runtime_for(graph);
    if (!gc || !wide || !runtime->gc_base) { ah_free(wide); return false; }
    wchar_t *attrs[] = {const_cast<wchar_t *>(L"objectSid"), const_cast<wchar_t *>(L"objectGUID"), const_cast<wchar_t *>(L"sAMAccountType"), const_cast<wchar_t *>(L"objectClass"), const_cast<wchar_t *>(L"flags"), nullptr};
    LDAPMessage *result = nullptr; struct l_timeval timeout = {ah_ldap_query_timeout_seconds, 0};
    ULONG status = ah_ldap_search_retry(gc, runtime->gc_base, LDAP_SCOPE_SUBTREE, wide, attrs, 0, nullptr, nullptr, &timeout, 0, &result);
    ah_free(wide);
    if (!status) for (LDAPMessage *entry = result ? WLDAP32$ldap_first_entry(gc, result) : nullptr; entry; entry = WLDAP32$ldap_next_entry(gc, entry)) consume(gc, entry);
    if (result) WLDAP32$ldap_msgfree(result);
    return !status && !graph.arena.failed;
}

static bool ah_gc_user_matches(ah_graph &graph, const char *account, ah_session_info **matches) {
    ah_directory_guard guard(graph);
    *matches = nullptr;
    auto *runtime = ah_runtime_for(graph);
    if (!runtime) return false;
    if(ah_current_cache){if(const auto *entry=ah_cached_gc(account)){for(auto *value=entry->values;value;value=value->next)ah_add_session(graph.arena,matches,value->value,account,0,0);return !graph.arena.failed;}}
    else for(auto *entry=runtime->cache;entry;entry=entry->next)if(ah_eq(entry->name,account)){
        ah_session_info **tail=matches;
        for(auto *source=entry->matches;source;source=source->next){
            auto *copy=graph.arena.make<ah_session_info>();if(!copy)return false;
            *copy=*source;copy->sid=graph.arena.copy(source->sid);copy->name=graph.arena.copy(source->name);copy->computer_sid=source->computer_sid?graph.arena.copy(source->computer_sid):nullptr;copy->next=nullptr;
            if(graph.arena.failed)return false;
            *tail=copy;tail=&copy->next;
        }
        return true;
    }
    char *escaped = ah_filter_escape(graph.arena, account);
    char *filter = escaped ? ah_concat(graph.arena, "(&(|(samAccountType=805306368)(samAccountType=805306370))(samaccountname=", ah_concat(graph.arena, escaped, ")", ")")) : nullptr;
    bool success = ah_gc_search(graph, filter, [&](LDAP *ld, LDAPMessage *entry) {
        struct berval **values = WLDAP32$ldap_get_values_lenW(ld, entry, const_cast<wchar_t *>(L"objectSid"));
        if (values && values[0]) {
            const char *sid = ah_sid(graph.arena, reinterpret_cast<unsigned char *>(values[0]->bv_val), values[0]->bv_len);
            if (sid) ah_add_session(graph.arena, matches, sid, account, 0, 0);
        }
        if (values) WLDAP32$ldap_value_free_len(values);
    });
    if(success&&ah_current_cache)ah_cache_gc(account,*matches);
    else if (success) {
        auto &storage=runtime->cache_storage;
        auto *entry = storage.make<ah_gc_cache_entry>();
        if(entry){
            entry->name=storage.copy(account);ah_session_info **tail=&entry->matches;
            for(auto *source=*matches;source&&!storage.failed;source=source->next){
                auto *copy=storage.make<ah_session_info>();if(!copy)break;
                *copy=*source;copy->sid=storage.copy(source->sid);copy->name=storage.copy(source->name);copy->computer_sid=source->computer_sid?storage.copy(source->computer_sid):nullptr;copy->next=nullptr;*tail=copy;tail=&copy->next;
            }
            if(!storage.failed){entry->next=runtime->cache;runtime->cache=entry;}
        }
    }
    return success && !graph.arena.failed;
}

static bool ah_resolve_directory_sid_gc(ah_graph &graph, const char *sid, const char **id, const char **kind) {
    if (auto *object = graph.sids.find(sid)) if (object->id && object->kind && !ah_eq(object->kind,"Base")) { *id = object->id; *kind = object->kind; return true; }
    unsigned char binary[68]; size_t length = 0;
    if (!ah_gpo_sid_bytes(sid, binary, length)) return false;
    ah_buffer filter(1024); AH_TEXT(&filter, "(objectSid="); static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) { char escaped[] = {'\\',hex[binary[i] >> 4],hex[binary[i] & 15]}; ah_append(&filter,escaped,3); }
    AH_TEXT(&filter, ")\0"); bool found = false;
    bool success = !filter.failed && ah_gc_search(graph, filter.data, [&](LDAP *ld, LDAPMessage *entry) {
        struct berval **values = WLDAP32$ldap_get_values_lenW(ld, entry, const_cast<wchar_t *>(L"sAMAccountType"));
        uint64_t type = values && values[0] ? ah_unsigned(graph.arena.copy(values[0]->bv_val, values[0]->bv_len)) : 0;
        if (values) WLDAP32$ldap_value_free_len(values);
        const char *label = type == 805306369 ? "Computer" : type == 805306368 || type == 805306370 ? "User" : type == 268435456 || type == 268435457 || type == 536870912 || type == 536870913 ? "Group" : nullptr;
        values = WLDAP32$ldap_get_values_lenW(ld, entry, const_cast<wchar_t *>(L"objectClass"));
        for (size_t i = 0; values && values[i]; ++i) {
            const char *name = graph.arena.copy(values[i]->bv_val, values[i]->bv_len);
            if (ah_eq(name, "msDS-ManagedServiceAccount") || ah_eq(name, "msDS-GroupManagedServiceAccount")) label = "User";
        }
        if (values) WLDAP32$ldap_value_free_len(values);
        if (label) { *id = graph.arena.copy(sid); *kind = label; found = true; }
    });
    return success && found;
}

static const char *ah_runtime_value(ah_graph &graph,LDAP *ld,LDAPMessage *entry,const wchar_t *name) {
    struct berval **values=WLDAP32$ldap_get_values_lenW(ld,entry,const_cast<wchar_t *>(name));
    const char *value=values&&values[0]?graph.arena.copy(values[0]->bv_val,values[0]->bv_len):nullptr;
    if(values)WLDAP32$ldap_value_free_len(values);
    return value;
}
static bool ah_runtime_wellknown_reference(ah_graph &graph, const char *dn, const char *identifier, const char **id, const char **kind) {
    const char *sid = nullptr;
    const char *label = ah_wellknown_identifier_kind(identifier, &sid);
    if (!label) return false;
    ah_object context = {}; context.dn = const_cast<char *>(dn);
    const char *domain = ah_eq(sid, "S-1-5-9") ? graph.forest_domain() : graph.object_domain(&context);
    *id = ah_concat(graph.arena, domain, "-", sid); *kind = label;
    return *id && !graph.arena.failed;
}
static bool ah_runtime_reference(ah_graph &graph,LDAP *ld,LDAPMessage *entry,const char *dn,const char **id,const char **kind) {
    struct berval **values = WLDAP32$ldap_get_values_lenW(ld,entry,const_cast<wchar_t *>(L"objectSid"));
    const char *identifier=values&&values[0]?ah_sid(graph.arena,reinterpret_cast<unsigned char *>(values[0]->bv_val),values[0]->bv_len):nullptr;
    if(values)WLDAP32$ldap_value_free_len(values);

    if (ah_wellknown_kind(identifier)) return ah_runtime_wellknown_reference(graph, dn, identifier, id, kind);
    const char *label=nullptr;bool builtin_domain=false;

    ah_object description={};description.dn=const_cast<char *>(dn);
    values=WLDAP32$ldap_get_values_lenW(ld,entry,const_cast<wchar_t *>(L"objectClass"));
    for(size_t i=0;values&&values[i];++i) {
        const char *name=graph.arena.copy(values[i]->bv_val,values[i]->bv_len);
        if(name)graph.directory.value(graph.directory.attribute(&description,"objectClass"),name,ah_len(name));
    }
    if(values)WLDAP32$ldap_value_free_len(values);
    auto has=[&](const char *name){return ah_has(&description,"objectClass",name);};
    const char *account=ah_runtime_value(graph,ld,entry,L"sAMAccountType");
    const uint64_t account_type=account?ah_unsigned(account):0;
    builtin_domain=has("builtinDomain");
    if(has("msDS-ManagedServiceAccount")||has("msDS-GroupManagedServiceAccount"))label="User";
    else if(account_type==805306369)label="Computer";
    else if(account_type==805306368||account_type==805306370)label="User";
    else if(account_type==268435456||account_type==268435457||account_type==536870912||account_type==536870913)label="Group";
    else if(has("groupPolicyContainer"))label="GPO";
    else if(has("organizationalUnit"))label="OU";
    else if(has("domainDNS")||has("domain"))label="Domain";
    else if(has("container"))label="Container";
    else if(has("configuration"))label="Configuration";
    else if(builtin_domain||has("sitesContainer"))label="Container";
    else if(has("pKICertificateTemplate"))label="CertTemplate";
    else if(has("pKIEnrollmentService"))label="EnterpriseCA";
    else if(has("certificationAuthority")) {
        if(ah_dn_contains(dn,"CN=Certification Authorities,CN=Public Key Services,CN=Services"))label="RootCA";
        if(ah_dn_contains(dn,"CN=AIA,CN=Public Key Services,CN=Services"))label="AIACA";
        if(ah_dn_contains(dn,"CN=NTAuthCertificates,CN=Public Key Services,CN=Services"))label="NTAuthStore";
    } else if(has("msPKI-Enterprise-Oid")) {
        if(ah_prefix(dn,"CN=OID,CN=Public Key Services,CN=Services"))label="Container";
        else if(const char *flags=ah_runtime_value(graph,ld,entry,L"flags");flags&&ah_unsigned(flags)==2)label="IssuancePolicy";
    } else if(has("site"))label="Site";
    else if(has("server")) {
        for(const char *parent=dn;*parent;parent=ah_parent(parent))
            if(ah_dn_starts_with(parent,"CN=Sites,CN=Configuration,")){label="SiteServer";break;}
    } else if(has("subnet"))label="SiteSubnet";
    if(!identifier||builtin_domain) {
        values=WLDAP32$ldap_get_values_lenW(ld,entry,const_cast<wchar_t *>(L"objectGUID"));
        identifier=values&&values[0]?ah_guid(graph.arena,reinterpret_cast<unsigned char *>(values[0]->bv_val),values[0]->bv_len):nullptr;
        if(values)WLDAP32$ldap_value_free_len(values);
    } else if(ah_builtin(identifier)) {
        ah_object context={};context.dn=const_cast<char *>(dn);
        identifier=ah_concat(graph.arena,ah_eq(identifier,"S-1-5-9")?graph.forest_domain():graph.object_domain(&context),"-",identifier);
    }
    if(identifier){*id=identifier;*kind=label?label:"Base";return true;}
    return false;
}
static bool ah_resolve_directory_sid_uncached(ah_graph &graph,const char *sid,const char **id,const char **kind) {
    ah_directory_guard guard(graph);
    if(ah_builtin(sid)) {
        *id=ah_concat(graph.arena,ah_eq(sid,"S-1-5-9")?graph.forest_domain():graph.domain,"-",sid);
        *kind=ah_wellknown_kind(sid);return *id&&*kind&&!graph.arena.failed;
    }
    if(ah_resolve_directory_sid_gc(graph,sid,id,kind))return true;
    auto *runtime=ah_runtime_for(graph);
    if(!ah_runtime_primary(runtime))return false;
    unsigned char binary[68];size_t size=0;if(!ah_gpo_sid_bytes(sid,binary,size))return false;
    ah_buffer filter(1024);AH_TEXT(&filter,"(objectSid=");static const char hex[]="0123456789abcdef";
    for(size_t i=0;i<size;++i){char escaped[]={'\\',hex[binary[i]>>4],hex[binary[i]&15]};ah_append(&filter,escaped,3);}
    AH_TEXT(&filter,")\0");wchar_t *wide=ah_wide(filter.data);if(!wide)return false;
    bool found=false;
    auto query=[&](LDAP *ld,wchar_t *base,ULONG scope) {
        wchar_t *attrs[]={const_cast<wchar_t *>(L"objectSid"),const_cast<wchar_t *>(L"objectGUID"),const_cast<wchar_t *>(L"objectClass"),const_cast<wchar_t *>(L"sAMAccountType"),const_cast<wchar_t *>(L"sAMAccountName"),const_cast<wchar_t *>(L"msDS-GroupMSAMembership"),const_cast<wchar_t *>(L"flags"),nullptr};
        LDAPMessage *result=nullptr;struct l_timeval timeout={ah_ldap_query_timeout_seconds,0};
        ULONG status=ah_ldap_search_retry(ld,base,scope,wide,attrs,0,nullptr,nullptr,&timeout,0,&result);
        for(LDAPMessage *entry=!status&&result?WLDAP32$ldap_first_entry(ld,result):nullptr;entry&&!found;entry=WLDAP32$ldap_next_entry(ld,entry)) {
            wchar_t *entry_dn=WLDAP32$ldap_get_dnW(ld,entry);
            char *dn=entry_dn?graph.arena.utf8(entry_dn):nullptr;
            if(dn)found=ah_runtime_reference(graph,ld,entry,dn,id,kind)&&!ah_eq(*kind,"Base");
            if(entry_dn)WLDAP32$ldap_memfreeW(entry_dn);
        }
        if(result)WLDAP32$ldap_msgfree(result);
    };
    wchar_t *base=ah_root(runtime->primary,L"defaultNamingContext");
    if(base){query(runtime->primary,base,LDAP_SCOPE_SUBTREE);ah_free(base);}
    if(!found) {
        char *binding=ah_concat(graph.arena,"<SID=",sid,">");base=binding?ah_wide(binding):nullptr;
        if(base){query(runtime->primary,base,LDAP_SCOPE_BASE);ah_free(base);}
    }
    const char *domain=nullptr,*domain_sid=nullptr;
    if(!found){const char *rid=sid;for(const char *p=sid;*p;++p)if(*p=='-')rid=p;domain_sid=static_cast<unsigned char>(binary[1])==4?graph.arena.copy(sid):graph.arena.copy(sid,static_cast<size_t>(rid-sid));ah_cache_domain(domain_sid,&domain);}
    if(!found) {
        PDS_DOMAIN_TRUSTSW trusts=nullptr;ULONG count=0;
        if(!domain&&NETAPI32$DsEnumerateDomainTrustsW(const_cast<wchar_t *>(ah_current_dc),DS_DOMAIN_VALID_FLAGS,&trusts,&count)==ERROR_SUCCESS&&trusts&&count<=4096) {
            for(ULONG i=0;i<count&&!domain;++i) {
                auto *raw=static_cast<const unsigned char *>(trusts[i].DomainSid);
                if(!raw||raw[0]!=1||raw[1]>15||!trusts[i].DnsDomainName)continue;
                const char *domain_sid=ah_sid(graph.arena,raw,8+4*raw[1]);size_t length=ah_len(domain_sid);
                if(domain_sid&&ah_prefix(sid,domain_sid)&&(sid[length]=='-'||!sid[length]))domain=graph.arena.utf8(trusts[i].DnsDomainName);
            }
        }
        if(trusts)NETAPI32$NetApiBufferFree(trusts);
        if(!domain) {
            wchar_t account[1024],name[1024];DWORD account_size=1024,name_size=1024;SID_NAME_USE usage=SidTypeUnknown;
            if(ADVAPI32$LookupAccountSidW(nullptr,binary,account,&account_size,name,&name_size,&usage)&&*name)domain=graph.arena.utf8(name);
        }
        if(domain_sid&&domain){ah_cache_add_domain(domain_sid,domain);ah_cache_add_domain(domain,domain_sid);}
        wchar_t *name=domain?ah_wide(domain):nullptr;PDOMAIN_CONTROLLER_INFOW dc=nullptr;
        if(name&&NETAPI32$DsGetDcNameW(nullptr,name,nullptr,nullptr,DS_DIRECTORY_SERVICE_REQUIRED|DS_RETURN_DNS_NAME,&dc)==ERROR_SUCCESS&&dc) {
            const wchar_t *host=dc->DomainControllerName;if(host&&host[0]=='\\'&&host[1]=='\\')host+=2;
            ULONG status=0;LDAP *ld=host?ah_open_directory(host,runtime->options,false,10,status):nullptr;
            if(ld){base=ah_root(ld,L"defaultNamingContext");if(base){query(ld,base,LDAP_SCOPE_SUBTREE);ah_free(base);}ah_close_directory(ld);}
        }
        if(dc)NETAPI32$NetApiBufferFree(dc);
        ah_free(name);
    }
    ah_free(wide);return found&&!graph.arena.failed;
}
static bool ah_resolve_directory_sid(ah_graph &graph,const char *sid,const char **id,const char **kind){
    if(graph.root&&graph.root->raw_sid){ah_cache_add_domain(graph.root->raw_sid,graph.domain);ah_cache_add_domain(graph.domain,graph.root->raw_sid);}
    if(ah_builtin(sid))return ah_resolve_directory_sid_uncached(graph,sid,id,kind);
    if(ah_cached_unresolved(sid))return false;
    if(ah_cache_type(sid,kind)){*id=graph.arena.copy(sid);return *id!=nullptr;}
    bool found=ah_resolve_directory_sid_uncached(graph,sid,id,kind);
    if(found)ah_cache_add_type(sid,*kind);else if(auto *runtime=ah_runtime_for(graph);runtime&&runtime->primary)ah_cache_unresolved(sid);
    if(!found)ah_observe_unresolvable();
    return found;
}
static bool ah_resolve_directory_dn_uncached(ah_graph &graph, const char *dn, const char **id, const char **kind) {
    ah_directory_guard guard(graph);
    if (auto *object = graph.dns.find(dn)) {
        if(object->raw_sid&&ah_builtin(object->raw_sid)) {
            *id=ah_concat(graph.arena,ah_eq(object->raw_sid,"S-1-5-9")?graph.forest_domain():graph.object_domain(object),"-",object->raw_sid);
            *kind=ah_wellknown_kind(object->raw_sid);return *id&&*kind;
        }
        if (object->id && object->kind && !ah_eq(object->kind,"Base")) {
            *id=object->id;
            *kind=ah_weq(object->type,L"issuancepolicies")&&!ah_eq(object->kind,"IssuancePolicy")?"Base":object->kind;return true;
        }
    }
    char *escaped = ah_filter_escape(graph.arena, dn);
    char *filter = escaped ? ah_concat(graph.arena, "(distinguishedName=", escaped, ")") : nullptr;
    bool found = false;
    ah_gc_search(graph, filter, [&](LDAP *ld, LDAPMessage *entry) { if(ah_runtime_reference(graph,ld,entry,dn,id,kind))found=true; });
    if(found)return true;
    auto *runtime=ah_runtime_for(graph);
    if(!ah_runtime_primary(runtime))return false;
    wchar_t *base=ah_wide(dn);if(!base)return false;
    wchar_t *attrs[]={const_cast<wchar_t *>(L"objectSid"),const_cast<wchar_t *>(L"objectGUID"),const_cast<wchar_t *>(L"objectClass"),const_cast<wchar_t *>(L"sAMAccountType"),const_cast<wchar_t *>(L"sAMAccountName"),const_cast<wchar_t *>(L"msDS-GroupMSAMembership"),const_cast<wchar_t *>(L"flags"),nullptr};
    auto query=[&](LDAP *ld) {
        LDAPMessage *result=nullptr;struct l_timeval timeout={ah_ldap_query_timeout_seconds,0};
        ULONG status=ah_ldap_search_retry(ld,base,LDAP_SCOPE_BASE,const_cast<wchar_t *>(L"(objectClass=*)"),attrs,0,nullptr,nullptr,&timeout,1,&result);
        LDAPMessage *entry=!status&&result?WLDAP32$ldap_first_entry(ld,result):nullptr;
        if(entry)found=ah_runtime_reference(graph,ld,entry,dn,id,kind);
        if(result)WLDAP32$ldap_msgfree(result);
    };
    query(runtime->primary);
    if(!found) {
        ah_object context={};context.dn=const_cast<char *>(dn);
        const char *domain=graph.object_domain(&context);
        if(domain&&*domain&&!ah_eq(domain,graph.domain)) {
            wchar_t *wide=ah_wide(domain);PDOMAIN_CONTROLLER_INFOW dc=nullptr;
            if(wide&&NETAPI32$DsGetDcNameW(nullptr,wide,nullptr,nullptr,DS_DIRECTORY_SERVICE_REQUIRED|DS_RETURN_DNS_NAME,&dc)==ERROR_SUCCESS&&dc) {
                const wchar_t *host=dc->DomainControllerName;if(host&&host[0]=='\\'&&host[1]=='\\')host+=2;
                ULONG status=0;LDAP *ld=host?ah_open_directory(host,runtime->options,false,10,status):nullptr;
                if(ld){query(ld);ah_close_directory(ld);}
            }
            if(dc)NETAPI32$NetApiBufferFree(dc);
            ah_free(wide);
        }
    }
    ah_free(base);return found&&!graph.arena.failed;
}

static bool ah_resolve_directory_dn(ah_graph &graph,const char *dn,const char **id,const char **kind){
    if(ah_cached_dn(dn,id,kind)) {
        if (ah_wellknown_identifier_kind(*id)) return ah_runtime_wellknown_reference(graph, dn, *id, id, kind);
        return *id!=nullptr;
    }
    bool found=ah_resolve_directory_dn_uncached(graph,dn,id,kind);
    if(!found)ah_observe_unresolvable();
    ah_cache_dn(dn,found?*id:nullptr,found?*kind:nullptr);return found;
}
static bool ah_resolve_certificate_template(ah_graph &graph,const char *property,const char *value,const char **id,const char **kind,const char **name) {
    ah_directory_guard guard(graph);
    auto *runtime=ah_runtime_for(graph);
    if(!ah_runtime_primary(runtime)||(!ah_eq(property,"cn")&&!ah_eq(property,"msPKI-Cert-Template-OID")))return false;
    char *escaped=ah_filter_escape(graph.arena,value);
    char *filter=escaped?ah_concat(graph.arena,"(&(objectClass=pKICertificateTemplate)(",property,"="):nullptr;
    filter=filter?ah_concat(graph.arena,filter,escaped,"))"):nullptr;
    wchar_t *wide=filter?ah_wide(filter):nullptr,*configuration=ah_root(runtime->primary,L"configurationNamingContext");
    if(!wide||!configuration){ah_free(wide);ah_free(configuration);return false;}
    size_t length=ah_wlen(configuration)+96;wchar_t *base=ah_alloc<wchar_t>(length*sizeof(wchar_t));
    if(!base){ah_free(wide);ah_free(configuration);return false;}
    MSVCRT$_snwprintf(base,length,L"CN=Certificate Templates,CN=Public Key Services,CN=Services,%ls",configuration);
    wchar_t *attrs[]={const_cast<wchar_t *>(L"objectGUID"),const_cast<wchar_t *>(L"name"),nullptr};
    LDAPMessage *result=nullptr;struct l_timeval timeout={ah_ldap_query_timeout_seconds,0};
    ULONG status=ah_ldap_search_retry(runtime->primary,base,LDAP_SCOPE_ONELEVEL,wide,attrs,0,nullptr,nullptr,&timeout,0,&result);
    LDAPMessage *entry=!status&&result?WLDAP32$ldap_first_entry(runtime->primary,result):nullptr;
    if(entry) {
        struct berval **values=WLDAP32$ldap_get_values_lenW(runtime->primary,entry,attrs[0]);
        if(values&&values[0])*id=ah_guid(graph.arena,reinterpret_cast<unsigned char *>(values[0]->bv_val),values[0]->bv_len);
        if(values)WLDAP32$ldap_value_free_len(values);
        *kind="CertTemplate";*name=ah_runtime_value(graph,runtime->primary,entry,L"name");
    }
    if(result)WLDAP32$ldap_msgfree(result);
    ah_free(base);ah_free(wide);ah_free(configuration);return entry&&*id&&!graph.arena.failed;
}

static bool ah_resolve_directory_account_sid(ah_graph &graph,const char *account,const char *domain,const char **id) {
    ah_directory_guard guard(graph);
    auto *runtime=ah_runtime_for(graph);
    if(!runtime||!account||!*account)return false;
    const char *wanted=domain&&*domain?domain:graph.domain;
    const char *cached_kind=nullptr,*cached_id=nullptr;
    if(ah_cached_account(account,wanted,&cached_id,&cached_kind)){
        *id=ah_builtin(cached_id)?ah_concat(graph.arena,ah_eq(cached_id,"S-1-5-9")?graph.forest_domain():graph.domain,"-",cached_id):graph.arena.copy(cached_id);return *id!=nullptr;
    }
    if(!ah_runtime_primary(runtime))return false;
    if(graph.root&&graph.root->raw_sid){ah_cache_add_domain(graph.root->raw_sid,graph.domain);ah_cache_add_domain(graph.domain,graph.root->raw_sid);}
    char *escaped=ah_filter_escape(graph.arena,account);
    char *filter=escaped?ah_concat(graph.arena,"(sAMAccountName=",escaped,")"):nullptr;
    wchar_t *wide=filter?ah_wide(filter):nullptr;
    if(!wide)return false;
    LDAP *ld=runtime->primary;bool owned=false;
    char *canonical=nullptr;
    if(!ah_eq(wanted,graph.domain)&&!*runtime->options.server) {
        wchar_t *name=ah_wide(wanted);PDOMAIN_CONTROLLER_INFOW dc=nullptr;
        if(name&&NETAPI32$DsGetDcNameW(nullptr,name,nullptr,nullptr,DS_DIRECTORY_SERVICE_REQUIRED|DS_RETURN_DNS_NAME,&dc)==ERROR_SUCCESS&&dc) {
            ah_arena names(65536);const char *dns=names.utf8(dc->DomainName);
            if(dns)canonical=ah_heap_copy(dns);
            if(dns&&!ah_eq(dns,graph.domain)) {
                const wchar_t *host=dc->DomainControllerName;if(host&&host[0]=='\\'&&host[1]=='\\')host+=2;
                ULONG status=0;ld=host?ah_open_directory(host,runtime->options,false,10,status):nullptr;owned=ld!=nullptr;
            }
        }
        if(dc)NETAPI32$NetApiBufferFree(dc);
        ah_free(name);
    }
    char *base_text=ah_domain_base(canonical?canonical:wanted);
    wchar_t *base=*runtime->options.server?ah_root(runtime->primary,L"defaultNamingContext"):base_text?ah_wide(base_text):nullptr;
    ah_free(canonical);ah_free(base_text);
    bool found=false;
    if(ld&&base) {
        wchar_t *attributes[]={const_cast<wchar_t *>(L"objectSid"),const_cast<wchar_t *>(L"sAMAccountType"),const_cast<wchar_t *>(L"objectGUID"),const_cast<wchar_t *>(L"objectClass"),const_cast<wchar_t *>(L"sAMAccountName"),const_cast<wchar_t *>(L"msDS-GroupMSAMembership"),const_cast<wchar_t *>(L"flags"),nullptr};
        LDAPMessage *result=nullptr;struct l_timeval timeout={ah_ldap_query_timeout_seconds,0};
        ULONG status=ah_ldap_search_retry(ld,base,LDAP_SCOPE_SUBTREE,wide,attributes,0,nullptr,nullptr,&timeout,1,&result);
        LDAPMessage *entry=!status&&result?WLDAP32$ldap_first_entry(ld,result):nullptr;
        if(entry){
            wchar_t *dn=WLDAP32$ldap_get_dnW(ld,entry);const char *text=dn?graph.arena.utf8(dn):graph.arena.utf8(base),*kind=nullptr;
            found=text&&ah_runtime_reference(graph,ld,entry,text,id,&kind);
            struct berval **values=WLDAP32$ldap_get_values_lenW(ld,entry,attributes[0]);
            const char *raw_id=values&&values[0]?ah_sid(graph.arena,reinterpret_cast<unsigned char *>(values[0]->bv_val),values[0]->bv_len):found?*id:nullptr;
            if(values)WLDAP32$ldap_value_free_len(values);
            if(found)ah_cache_account(account,wanted,raw_id,kind);
            if(dn)WLDAP32$ldap_memfreeW(dn);
        }
        if(result)WLDAP32$ldap_msgfree(result);
    }
    ah_free(base);ah_free(wide);if(owned)ah_close_directory(ld);
    return found&&!graph.arena.failed;
}
