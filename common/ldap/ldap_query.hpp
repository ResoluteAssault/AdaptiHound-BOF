#pragma once

static LDAP *ah_ldap_current(LDAP *handle);
static bool ah_ldap_recover(LDAP *&handle, bool same_server);
static void ah_close_directory(LDAP *handle);
static void ah_observe_ldap_begin();
static void ah_observe_ldap_end(ULONG, uint64_t);
static void ah_observe_retry();
static void ah_observe_timeout();
static void ah_drain_observability();

static inline wchar_t *ah_ldap_filter_normalize(const char *value) {
    wchar_t *wide=ah_wide(value);
    if(!wide)return nullptr;
    const size_t length=ah_wlen(wide);
    if(length>SIZE_MAX/sizeof(wchar_t)-3){ah_free(wide);return nullptr;}
    wchar_t *out=ah_alloc<wchar_t>((length+3)*sizeof(wchar_t));
    if(out){
        size_t n=0;
        if(!length||wide[0]!=L'(')out[n++]=L'(';
        for(size_t i=0;i<length;++i)out[n++]=wide[i];
        if(!length||wide[length-1]!=L')')out[n++]=L')';
        out[n]=0;
    }
    ah_free(wide);return out;
}

static void ah_ldap_backoff(unsigned int retry) {

    const DWORD delay=retry>=4?20000:static_cast<DWORD>(2000U<<retry);
    ah_observe_retry();ah_drain_observability();KERNEL32$Sleep(delay);ah_drain_observability();
}

struct ah_ldap_controls final {
    LDAPControlW **values=nullptr;
    explicit ah_ldap_controls(LDAPControlW **original) {
        size_t count=0;bool already=ah_ldap_scope_control==nullptr;
        for(;original&&original[count];++count){
            if(count>=SIZE_MAX/sizeof(*values)-2)return;
            if(ah_ldap_scope_control&&ah_weq(original[count]->ldctl_oid,ah_ldap_scope_control->ldctl_oid))already=true;
        }
        values=ah_alloc<LDAPControlW *>((count+(already?1:2))*sizeof(*values));
        if(!values)return;
        for(size_t i=0;i<count;++i)values[i]=original[i];
        if(!already)values[count++]=ah_ldap_scope_control;
        values[count]=nullptr;
    }
    ~ah_ldap_controls(){ah_free(values);}
    ah_ldap_controls(const ah_ldap_controls&)=delete;
    ah_ldap_controls&operator=(const ah_ldap_controls&)=delete;
};

static ULONG ah_ldap_search_once(LDAP *handle,wchar_t *base,ULONG scope,wchar_t *filter,wchar_t **attributes,
    ULONG attributes_only,LDAPControlW **controls,LDAPControlW **client_controls,l_timeval *timeout,
    ULONG size_limit,LDAPMessage **result) {
    const uint64_t started=KERNEL32$GetTickCount64();ah_observe_ldap_begin();
    const ULONG status=WLDAP32$ldap_search_ext_sW(handle,base,scope,filter,attributes,attributes_only,controls,client_controls,timeout,size_limit,result);
    ah_observe_ldap_end(status,KERNEL32$GetTickCount64()-started);
    if(status==LDAP_TIMEOUT)ah_observe_timeout();
    ah_drain_observability();
    return status;
}

struct ah_ldap_retry_state { unsigned int busy=0,recoveries=0; };
static ULONG ah_ldap_search_retry(LDAP *&handle,wchar_t *base,ULONG scope,wchar_t *filter,wchar_t **attributes,
    ULONG attributes_only,LDAPControlW **controls,LDAPControlW **client_controls,l_timeval *timeout,
    ULONG size_limit,LDAPMessage **result,bool same_server=false,ah_ldap_retry_state *query_state=nullptr) {
    ah_ldap_controls request_controls(controls);
    if(!request_controls.values){*result=nullptr;return LDAP_NO_MEMORY;}
    ah_ldap_retry_state local;
    ah_ldap_retry_state &retries=query_state?*query_state:local;
    for(;;){
        handle=ah_ldap_current(handle);*result=nullptr;
        const ULONG status=ah_ldap_search_once(handle,base,scope,filter,attributes,attributes_only,request_controls.values,client_controls,timeout,size_limit,result);
        if((status==LDAP_BUSY||status==LDAP_TIMEOUT)&&retries.busy<3){
            if(*result){WLDAP32$ldap_msgfree(*result);*result=nullptr;}
            ah_ldap_backoff(++retries.busy);continue;
        }
        if(status==LDAP_SERVER_DOWN&&retries.recoveries++<3){
            if(*result){WLDAP32$ldap_msgfree(*result);*result=nullptr;}
            bool recovered=false;
            for(unsigned int retry=0;retry<3&&!recovered;++retry){ah_ldap_backoff(retry);recovered=ah_ldap_recover(handle,same_server);}
            if(recovered)continue;
        }
        return status;
    }
}
