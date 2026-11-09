#pragma once
#include "native_api.hpp"
#include <cstdarg>
#include <psapi.h>

static int ah_verbosity = 2;
static bool ah_telemetry_enabled = false;
using ah_log_dispatch_fn = void (*)(int, const SYSTEMTIME &, const char *, const char *);
static ah_log_dispatch_fn ah_log_dispatch = nullptr;
static void ah_log_emit(int callback, const SYSTEMTIME &now, const char *name, const char *message) {
    if (ah_telemetry_enabled)
        BeaconPrintf(callback, "%04u-%02u-%02uT%02u:%02u:%02u.%03u|%s|%s", now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, name, message);
    else BeaconPrintf(callback, "%s", message);
}
static void ah_log_fallback(const char *message) {
    SYSTEMTIME time = {};
    if (ah_log_dispatch) ah_log_dispatch(CALLBACK_ERROR,time,"ERROR",message);
    else ah_log_emit(CALLBACK_ERROR,time,"ERROR",message);
}
static void ah_log_vprintf(int level, int callback, const char *format, va_list arguments) {
    if (level < ah_verbosity || (level < 2 && !ah_telemetry_enabled)) return;
    ah_native_library crt(L"msvcrt.dll"), kernel(L"kernel32.dll");
    using count_fn = int (__cdecl *)(const char *, va_list);
    using format_fn = int (__cdecl *)(char *, size_t, const char *, va_list);
    auto count = crt.find<count_fn>("_vscprintf");
    auto render = crt.find<format_fn>("vsnprintf");
    if (!render) render = crt.find<format_fn>("_vsnprintf");
    if (!count || !render) { ah_log_fallback("AdaptiHound: cannot format diagnostic output"); return; }
    va_list copy; va_copy(copy, arguments); int length = count(format, copy); va_end(copy);
    if (length < 0) return;
    char small[2048];
    char *message = static_cast<size_t>(length) < sizeof(small) ? small : ah_alloc(static_cast<size_t>(length) + 1);
    if (!message) { ah_log_fallback("AdaptiHound: cannot allocate diagnostic output"); return; }
    render(message, static_cast<size_t>(length) + 1, format, arguments);
    SYSTEMTIME now = {}; auto clock = kernel.find<decltype(&GetLocalTime)>("GetLocalTime"); if (clock) clock(&now);
    const char *names[] = {"TRACE", "DEBUG", "INFORMATION", "WARNING", "ERROR", "CRITICAL", "NONE"};
    const char *name = level >= 0 && level <= 6 ? names[level] : "LOG";
    if (ah_log_dispatch) ah_log_dispatch(callback, now, name, message);
    else ah_log_emit(callback, now, name, message);
    if (message != small) ah_free(message);
}
static void ah_log_level(int level, const char *format, ...) {
    va_list arguments; va_start(arguments, format); ah_log_vprintf(level, level >= 4 ? CALLBACK_ERROR : CALLBACK_OUTPUT, format, arguments); va_end(arguments);
}
static void ah_log_printf(int callback, const char *format, ...) {
    va_list arguments; va_start(arguments, format); ah_log_vprintf(callback == CALLBACK_ERROR ? 4 : 2, callback, format, arguments); va_end(arguments);
}
static void ah_log_telemetry(const char *format, ...) {
    if (!ah_telemetry_enabled) return;
    va_list arguments; va_start(arguments, format); ah_log_vprintf(2, CALLBACK_OUTPUT, format, arguments); va_end(arguments);
}

class ah_observability;
static ah_observability *ah_current_observability = nullptr;
class ah_observability final {
    using create_event_fn = HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
    using create_thread_fn = HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using wait_fn = DWORD (WINAPI *)(HANDLE, DWORD);
    using set_fn = BOOL (WINAPI *)(HANDLE);
    using thread_id_fn = DWORD (WINAPI *)();
    struct message { SYSTEMTIME time; int callback; const char *level; char *text; message *next; };
    ah_observability *previous;
    ah_log_dispatch_fn previous_dispatch;
    ah_native_library kernel, psapi;
    HANDLE stop = nullptr, thread = nullptr;
    wait_fn wait = nullptr; set_fn signal = nullptr;
    thread_id_fn thread_id = nullptr;
    DWORD creator = 0;
    message *messages = nullptr, *messages_tail = nullptr;
    uint64_t dropped = 0;
    uint64_t began = 0;
    alignas(8) volatile LONG64 next_status = 0, next_flush = 0;
    DWORD interval;
    bool metrics, telemetry;
    const char *prefix, *identifier;
    ah_buffer log;
    CRITICAL_SECTION state_lock = {};
    bool lock_initialized = false, stopped = false, published = false;
    volatile LONG stop_requested = 0;
    volatile LONG pass_active = 0;
    alignas(8) volatile LONG64 completed = 0, last_count = 0, pass_began = 0;
    alignas(8) volatile LONG64 inflight = 0, total = 0, failures = 0, retries = 0, timeouts = 0, unresolvable = 0, latency_sum = 0, buckets[7] = {};
    static uint64_t read(volatile LONG64 &value) { return static_cast<uint64_t>(InterlockedCompareExchange64(&value, 0, 0)); }
    struct guard { ah_observability &owner; explicit guard(ah_observability &value):owner(value) { if(owner.lock_initialized)KERNEL32$EnterCriticalSection(&owner.state_lock); } ~guard(){if(owner.lock_initialized)KERNEL32$LeaveCriticalSection(&owner.state_lock);} };
    static void dispatch(int callback, const SYSTEMTIME &time, const char *level, const char *text) {
        auto *self = ah_current_observability;
        if (!self) return;
        if (self->thread_id && self->thread_id() == self->creator) { self->drain(); ah_log_emit(callback,time,level,text); return; }
        auto *item = ah_alloc<message>(sizeof(message));
        char *copy = nullptr;
        if (item) { size_t length=ah_len(text);copy=ah_alloc(length+1);if(copy)for(size_t i=0;i<=length;++i)copy[i]=text[i]; }
        guard locked(*self);
        if (!item || !copy) { ah_free(item); ah_free(copy); ++self->dropped; return; }
        item->time=time;item->callback=callback;item->level=level;item->text=copy;
        if (self->messages_tail) self->messages_tail->next=item; else self->messages=item;
        self->messages_tail=item;
    }
    static DWORD WINAPI work(void *opaque) {
        auto &self = *static_cast<ah_observability *>(opaque);
        for (;;) {
            if(InterlockedCompareExchange(&self.stop_requested,0,0))break;
            uint64_t now = KERNEL32$GetTickCount64();
            uint64_t next = self.telemetry && InterlockedCompareExchange(&self.pass_active,0,0) ? read(self.next_status) : now+1000;
            if (self.metrics && read(self.next_flush) < next) next = read(self.next_flush);
            DWORD delay = next > now ? static_cast<DWORD>(next - now > 1000 ? 1000 : next - now) : 0;
            DWORD result = self.wait(self.stop, delay);
            if(InterlockedCompareExchange(&self.stop_requested,0,0))break;
            if (result == WAIT_OBJECT_0) continue;
            if (result != WAIT_TIMEOUT) return ERROR_GEN_FAILURE;
            now = KERNEL32$GetTickCount64();
            if (self.telemetry && InterlockedCompareExchange(&self.pass_active,0,0) && now >= read(self.next_status)) { self.status(); InterlockedExchange64(&self.next_status,static_cast<LONG64>(now+self.interval)); }
            if (self.metrics && now >= read(self.next_flush)) { self.flush(); InterlockedExchange64(&self.next_flush,static_cast<LONG64>(now+5000)); }
        }
        return ERROR_SUCCESS;
    }
    static void stamp(char (&text)[24]) {
        SYSTEMTIME now = {}; ah_native_library module(L"kernel32.dll"); auto clock=module.find<decltype(&GetLocalTime)>("GetLocalTime");if(clock)clock(&now);
        const unsigned int values[] = {now.wYear,now.wMonth,now.wDay,now.wHour,now.wMinute,now.wSecond,now.wMilliseconds};
        const unsigned int widths[] = {4,2,2,2,2,2,3}; const char separators[] = {'-','-',' ',':',':','.',0};
        size_t out=0;
        for(unsigned int i=0;i<7;++i){unsigned int divisor=widths[i]==4?1000:widths[i]==3?100:10;for(unsigned int n=0;n<widths[i];++n,divisor/=10)text[out++]=static_cast<char>('0'+values[i]/divisor%10);if(separators[i])text[out++]=separators[i];}
        text[out]=0;
    }
    void number(uint64_t value) { char digits[32]; const char *p=ah_decimal(digits+sizeof(digits),value);ah_append(&log,p,ah_len(p)); }
    void metric(const char *time,const char *name,uint64_t value,bool histogram=false,const char *bound=nullptr,bool include_identifier=true,const char *location="AdaptiHoundNativeLDAP") {
        ah_append(&log,time,23);AH_TEXT(&log," ");ah_append(&log,name,ah_len(name));
        AH_TEXT(&log,"{location=\"");ah_append(&log,location,ah_len(location));AH_TEXT(&log,"\"");
        if(include_identifier){
            AH_TEXT(&log,",identifier=\"");
            for(const char *p=identifier;*p;++p){if(*p=='"'||*p=='\\')AH_TEXT(&log,"\\");if(*p=='\n')AH_TEXT(&log,"\\n");else ah_append(&log,p,1);}
            AH_TEXT(&log,"\"");
        }
        if(bound){AH_TEXT(&log,",le=\"");ah_append(&log,bound,ah_len(bound));AH_TEXT(&log,"\"");}AH_TEXT(&log,"} = ");
        if(!histogram) { AH_TEXT(&log,"{"); }
        number(value);
        if(!histogram) { AH_TEXT(&log,"}"); }
        AH_TEXT(&log,"\n");
    }
public:
    ah_observability(int status_interval,bool enabled,const char *output_prefix,const char *domain,bool detailed=false)
        :previous(ah_current_observability),previous_dispatch(ah_log_dispatch),kernel(L"kernel32.dll"),psapi(L"psapi.dll"),interval(static_cast<DWORD>(status_interval)),metrics(enabled),telemetry(detailed),prefix(output_prefix),identifier(domain&&*domain?domain:"collector"),log(0,4096) {
        began=KERNEL32$GetTickCount64();pass_began=static_cast<LONG64>(began);next_status=began+interval;next_flush=began+5000;
        lock_initialized=KERNEL32$InitializeCriticalSectionAndSpinCount(&state_lock,4000)!=0;
        thread_id=kernel.find<thread_id_fn>("GetCurrentThreadId");creator=thread_id?thread_id():0;
        if(!lock_initialized||!creator){ah_log_level(4,"AdaptiHound: cannot initialize caller-affine diagnostics");return;}
        ah_current_observability=this;
        ah_log_dispatch=dispatch;
        published=true;
        if (!metrics && !telemetry) return;
        auto event=kernel.find<create_event_fn>("CreateEventW");auto create=kernel.find<create_thread_fn>("CreateThread");wait=kernel.find<wait_fn>("WaitForSingleObject");signal=kernel.find<set_fn>("SetEvent");
        if(lock_initialized&&creator&&event&&create&&wait&&signal){stop=event(nullptr,FALSE,FALSE,nullptr);if(stop)thread=create(nullptr,0,work,this,0,nullptr);}
        if(!thread){ah_log_level(4,"AdaptiHound: cannot start periodic status/metrics worker");ah_current_observability=previous;ah_log_dispatch=previous_dispatch;published=false;}
    }
    ~ah_observability(){finish();if(published){ah_current_observability=previous;ah_log_dispatch=previous_dispatch;}if(lock_initialized)KERNEL32$DeleteCriticalSection(&state_lock);}
    bool valid() const { return published && ((!metrics && !telemetry) || thread); }
    void drain(){
        if(!thread_id||thread_id()!=creator)return;
        message *head=nullptr;uint64_t lost=0;
        {guard locked(*this);head=messages;messages=messages_tail=nullptr;lost=dropped;dropped=0;}
        while(head){message *next=head->next;ah_log_emit(head->callback,head->time,head->level,head->text);ah_free(head->text);ah_free(head);head=next;}
        if(lost&&ah_verbosity<=4) { SYSTEMTIME empty={};ah_log_emit(CALLBACK_ERROR,empty,"ERROR","AdaptiHound: worker diagnostic queue exceeded memory budget"); }
    }
    void begin_pass(){drain();{guard locked(*this);uint64_t now=KERNEL32$GetTickCount64();InterlockedExchange64(&completed,0);InterlockedExchange64(&last_count,0);InterlockedExchange64(&pass_began,static_cast<LONG64>(now));InterlockedExchange64(&next_status,static_cast<LONG64>(now+interval));InterlockedExchange(&pass_active,1);}if(signal&&stop)signal(stop);}
    void end_pass(){InterlockedExchange(&pass_active,0);if(signal&&stop)signal(stop);drain();status();}
    void complete(){if(telemetry)InterlockedIncrement64(&completed);}
    void ldap_begin(){if(metrics||telemetry)InterlockedIncrement64(&inflight);}
    void ldap_end(ULONG status,uint64_t elapsed){
        if(!metrics&&!telemetry)return;
        guard locked(*this);
        InterlockedDecrement64(&inflight);InterlockedIncrement64(&total);
        if(status!=LDAP_SUCCESS&&status!=LDAP_NO_RESULTS_RETURNED)InterlockedIncrement64(&failures);
        InterlockedExchangeAdd64(&latency_sum,static_cast<LONG64>(elapsed));
        const uint64_t bounds[]={100,250,500,1000,2500,5000};unsigned int bucket=0;
        while(bucket<6&&elapsed>bounds[bucket])++bucket;
        InterlockedIncrement64(&buckets[bucket]);
    }
    void retry(){if(metrics||telemetry)InterlockedIncrement64(&retries);}void timeout(){if(metrics||telemetry)InterlockedIncrement64(&timeouts);}void unresolved(){if(metrics||telemetry)InterlockedIncrement64(&unresolvable);}
    void status(){if(!telemetry)return;uint64_t count=0,before=0,elapsed=0;{guard locked(*this);count=read(completed);before=read(last_count);elapsed=KERNEL32$GetTickCount64()-read(pass_began);InterlockedExchange64(&last_count,static_cast<LONG64>(count));}PROCESS_MEMORY_COUNTERS_EX info={};info.cb=sizeof(info);auto query=psapi.find<decltype(&GetProcessMemoryInfo)>("GetProcessMemoryInfo");bool known=query&&query(reinterpret_cast<HANDLE>(static_cast<intptr_t>(-1)),reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&info),sizeof(info));
        ah_log_level(2,"Status: %llu objects finished (+%llu %llu.%03llu)/s -- Using %llu MB RAM%s",static_cast<unsigned long long>(count),static_cast<unsigned long long>(count-before),static_cast<unsigned long long>(elapsed?count*1000/elapsed:0),static_cast<unsigned long long>(elapsed?(count*1000000/elapsed)%1000:0),static_cast<unsigned long long>(known?info.PrivateUsage/1024/1024:0),known?"":" (process memory unavailable)");}
    void flush(){if(!metrics)return;guard locked(*this);char time[24];stamp(time);AH_TEXT(&log,"Metric Flush: ");ah_append(&log,time,23);AH_TEXT(&log,"\n========================================\n");metric(time,"ldap_total_requests",read(total));metric(time,"ldap_failed_requests",read(failures));metric(time,"ldap_concurrent_requests",read(inflight));uint64_t cumulative=0;const char *bounds[]={"100","250","500","1000","2500","5000","+Inf"};for(unsigned int i=0;i<7;++i){cumulative+=read(buckets[i]);metric(time,"ldap_request_duration_milliseconds_bucket",cumulative,true,bounds[i]);}metric(time,"ldap_request_duration_milliseconds_sum",read(latency_sum),true);metric(time,"ldap_request_duration_milliseconds_count",read(total),true);metric(time,"ldap_total_unresolvable_principals",read(unresolvable),false,nullptr,false,"LdapUtils");metric(time,"adaptihound_ldap_timeouts",read(timeouts));metric(time,"adaptihound_ldap_retries",read(retries));AH_TEXT(&log,"========================================\n\n\n\n\n");}
    void finish(){if(stopped)return;stopped=true;InterlockedExchange(&stop_requested,1);if(thread){signal(stop);while(wait(thread,INFINITE)!=WAIT_OBJECT_0)KERNEL32$Sleep(1);KERNEL32$CloseHandle(thread);thread=nullptr;}if(stop){KERNEL32$CloseHandle(stop);stop=nullptr;}if(!published)return;drain();if(InterlockedCompareExchange(&pass_active,0,0))end_pass();flush();
        if(telemetry)ah_log_telemetry("AdaptiHound: LDAP requests %llu; failures %llu; timeouts %llu; unresolved principals %llu",static_cast<unsigned long long>(read(total)),static_cast<unsigned long long>(read(failures)),static_cast<unsigned long long>(read(timeouts)),static_cast<unsigned long long>(read(unresolvable)));
        if(metrics){if(log.failed||log.length>0x7fffffffU){ah_log_level(4,"AdaptiHound: metrics log exceeded memory/Downloads capacity");return;}ah_arena names(0,256);const char *name=prefix&&*prefix?ah_concat(names,prefix,"_metrics.log"):"metrics.log";if(!name){ah_log_level(4,"AdaptiHound: cannot allocate metrics filename");return;}AxDownloadMemory(const_cast<char *>(name),log.data,static_cast<int>(log.length));}}
    ah_observability(const ah_observability&)=delete;ah_observability&operator=(const ah_observability&)=delete;
};
[[maybe_unused]] static void ah_observe_ldap_begin(){if(ah_current_observability)ah_current_observability->ldap_begin();}
[[maybe_unused]] static void ah_observe_ldap_end(ULONG status,uint64_t elapsed){if(ah_current_observability)ah_current_observability->ldap_end(status,elapsed);}
[[maybe_unused]] static void ah_observe_retry(){if(ah_current_observability)ah_current_observability->retry();}
[[maybe_unused]] static void ah_observe_timeout(){if(ah_current_observability)ah_current_observability->timeout();}
[[maybe_unused]] static void ah_observe_unresolvable(){if(ah_current_observability)ah_current_observability->unresolved();}
[[maybe_unused]] static void ah_observe_object_completed(){if(ah_current_observability)ah_current_observability->complete();}
[[maybe_unused]] static void ah_observe_begin_pass(){if(ah_current_observability)ah_current_observability->begin_pass();}
[[maybe_unused]] static void ah_observe_end_pass(){if(ah_current_observability)ah_current_observability->end_pass();}
[[maybe_unused]] static void ah_drain_observability(){if(ah_current_observability)ah_current_observability->drain();}

#define BeaconPrintf ah_log_printf
