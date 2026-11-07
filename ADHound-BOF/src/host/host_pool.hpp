#pragma once
#include <new>

static bool ah_parallel_directory_ready();

class ah_host_pool final {
public:
    using selected_fn = bool (*)(ah_graph &, const ah_object *);
    using collect_fn = void (*)(ah_graph &, ah_object *, const wchar_t *, int);
private:
    using create_fn = HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using wait_fn = DWORD (WINAPI *)(HANDLE, DWORD);
    using exit_fn = BOOL (WINAPI *)(HANDLE, LPDWORD);
    using open_token_fn = BOOL (WINAPI *)(HANDLE, DWORD, BOOL, PHANDLE);
    using set_token_fn = BOOL (WINAPI *)(PHANDLE, HANDLE);
    struct task { ah_object *original; ah_object result; };
    struct worker final {
        ah_host_pool &pool;
        ah_directory directory;
        ah_graph graph;
        HANDLE thread = nullptr;
        worker *next = nullptr;
        worker(ah_host_pool &owner, size_t limit) : pool(owner), directory(limit), graph(directory, owner.source.ad) {}
    };
    ah_graph &source;
    size_t maximum;
    ah_arena control;
    ah_native_library kernel, advapi;
    task *tasks = nullptr;
    size_t task_count = 0, capacity = 0;
    worker *workers = nullptr;
    HANDLE token = nullptr;
    create_fn create = nullptr;
    wait_fn wait = nullptr;
    exit_fn exit_code = nullptr;
    set_token_fn set_token = nullptr;
    collect_fn callback = nullptr;
    const wchar_t *controller = nullptr;
    int methods = 0;
    volatile LONG cursor = -1, failed = 0;
    bool used = false;
    DWORD failure_code = ERROR_SUCCESS;
    unsigned int started = 0;
    LONG token_failures_before = 0;

    bool prepare(worker &state) {
        ah_graph &g = state.graph;

        state.directory.objects = source.directory.objects;
        state.directory.count = source.directory.count;
        g.dns = source.dns.read_only_view(g.arena);
        g.sids = source.sids.read_only_view(g.arena);
        g.hosts = source.hosts.read_only_view(g.arena);
        g.accounts = source.accounts.read_only_view(g.arena);
        g.principals = source.principals.read_only_view(g.arena);
        g.root = source.root; g.domain = source.domain;
        g.forest_name = source.forest_domain();
        g.laps_guid = source.laps_guid; g.laps_guid_v2 = source.laps_guid_v2; g.laps_guid_v3 = source.laps_guid_v3;
        g.domain_names = source.domain_names;
        return !g.arena.failed && !source.arena.failed;
    }
    static DWORD WINAPI work(void *parameter) {
        worker &state = *static_cast<worker *>(parameter);
        ah_host_pool &pool = state.pool;

        if (pool.token && !pool.set_token(nullptr, pool.token)) {
            InterlockedExchange(&pool.failed, 1); return ERROR_ACCESS_DENIED;
        }

        void *directory_runtime = nullptr;
        const bool runtime_required = ah_worker_directory_runtime_required();
        if (runtime_required) {
            directory_runtime = ah_create_worker_directory_runtime();
            if (!directory_runtime) InterlockedExchange(&pool.failed, 1);
        }
        const bool runtime_failed = runtime_required && !directory_runtime;
        state.graph.directory_runtime = directory_runtime;
        for (;;) {
            if (InterlockedCompareExchange(&pool.failed, 0, 0)) break;
            LONG index = InterlockedIncrement(&pool.cursor);
            if (index < 0 || static_cast<size_t>(index) >= pool.task_count) break;
            task &item = pool.tasks[index];
            pool.callback(state.graph, &item.result, pool.controller, pool.methods);
            if (state.graph.arena.failed || ah_token_restore_failures != pool.token_failures_before) { InterlockedExchange(&pool.failed, 1); break; }
        }
        if (directory_runtime) ah_destroy_worker_directory_runtime(directory_runtime);
        state.graph.directory_runtime = nullptr;
        if (pool.token && !pool.set_token(nullptr, nullptr)) {
            InterlockedExchange(&pool.failed, 1);
            return ERROR_ACCESS_DENIED;
        }
        return runtime_failed ? ERROR_NOT_ENOUGH_MEMORY : ERROR_SUCCESS;
    }
    void join() {
        for (worker *state = workers; state; state = state->next) if (state->thread) {

            while (wait(state->thread, 50) != WAIT_OBJECT_0) {
                ah_drain_observability();
                DWORD code = STILL_ACTIVE;
                if (exit_code(state->thread, &code) && code != STILL_ACTIVE) break;
                KERNEL32$Sleep(1);
            }
            DWORD code = ERROR_GEN_FAILURE;
            if (!exit_code(state->thread, &code) || code != ERROR_SUCCESS) InterlockedExchange(&failed, 1);
            KERNEL32$CloseHandle(state->thread); state->thread = nullptr;
        }
    }
    void merge() {
        for (size_t i = 0; i < task_count; ++i) {
            ah_object *o = tasks[i].original;
            const ah_object before = *o;
            *o = tasks[i].result;

            o->type = before.type; o->dn = before.dn; o->id = before.id; o->raw_sid = before.raw_sid; o->kind = before.kind;
            o->attributes = before.attributes;
            o->next = before.next; o->parent = before.parent; o->children = before.children; o->sibling = before.sibling;
            o->exported = before.exported; o->auxiliary_only = before.auxiliary_only;
            o->explicit_target = before.explicit_target; o->stealth_targeted = before.stealth_targeted;
        }
        for (worker *state = workers; state; state = state->next) {
            if (!state->directory.call_status) continue;
            if (source.directory.call_status_tail) source.directory.call_status_tail->next = state->directory.call_status;
            else source.directory.call_status = state->directory.call_status;
            source.directory.call_status_tail = state->directory.call_status_tail;
            state->directory.call_status = state->directory.call_status_tail = nullptr;
        }
    }
public:
    ah_host_pool(ah_graph &graph, size_t limit) : source(graph), maximum(limit), control(limit), kernel(L"kernel32.dll"), advapi(L"advapi32.dll") {}
    ~ah_host_pool() {
        join();
        if (token) KERNEL32$CloseHandle(token);
        while (workers) { worker *next = workers->next; workers->~worker(); ah_free(workers); workers = next; }
    }
    bool collect(const wchar_t *dc, int collection, int threads, selected_fn selected, collect_fn collect_host = ah_collect_host_sessions) {
        if (used || threads < 1 || !selected || !collect_host) return false;
        used = true;
        size_t total = 0;
        for (ah_object *o = source.directory.objects; o; o = o->next) if (selected(source, o)) {
            if (total == SIZE_MAX) { failure_code = ERROR_ARITHMETIC_OVERFLOW; return false; }
            ++total;
        }
        if (!total) return true;
        if (threads == 1 || total == 1) {
            for (ah_object *o = source.directory.objects; o && !source.arena.failed; o = o->next)
                if (selected(source, o)) collect_host(source, o, dc, collection);
            return !source.arena.failed;
        }
        if (!ah_parallel_directory_ready()) return false;
        create = kernel.find<create_fn>("CreateThread"); wait = kernel.find<wait_fn>("WaitForSingleObject");
        exit_code = kernel.find<exit_fn>("GetExitCodeThread"); set_token = advapi.find<set_token_fn>("SetThreadToken");
        auto open = advapi.find<open_token_fn>("OpenThreadToken");
        if (!create || !wait || !exit_code || !set_token || !open) return false;
        if (!open(reinterpret_cast<HANDLE>(static_cast<intptr_t>(-2)), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &token) && KERNEL32$GetLastError() != ERROR_NO_TOKEN) return false;
        const unsigned int count = total < static_cast<size_t>(threads) ? static_cast<unsigned int>(total) : static_cast<unsigned int>(threads);
        capacity = count < 1000 ? 1000 : count;
        if (capacity > total) capacity = total;
        if (capacity > SIZE_MAX / sizeof(task)) { failure_code = ERROR_ARITHMETIC_OVERFLOW; return false; }
        tasks = static_cast<task *>(control.alloc(capacity * sizeof(task)));
        if (!tasks) return false;
        controller = dc; methods = collection; callback = collect_host;
        for (unsigned int i = 0; i < count; ++i) {
            worker *state = ah_alloc<worker>(sizeof(worker));
            if (!state) return false;
            new (state) worker(*this, maximum);
            state->next = workers; workers = state;
            if (!prepare(*state)) return false;
        }
        const bool diagnostics = ah_host_diagnostics;
        token_failures_before = ah_token_restore_failures;
        ah_host_diagnostics = false;
        ah_object *next = source.directory.objects;
        while (next && !InterlockedCompareExchange(&failed, 0, 0)) {
            task_count = 0;
            while (next && task_count < capacity) {
                ah_object *object = next; next = next->next;
                if (selected(source, object)) {
                    tasks[task_count].original = object;
                    tasks[task_count++].result = *object;
                }
            }
            if (!task_count) continue;
            cursor = -1;
            for (worker *state = workers; state; state = state->next) {
                state->thread = create(nullptr, 0, work, state, 0, nullptr);
                if (!state->thread) { failure_code = KERNEL32$GetLastError(); InterlockedExchange(&failed, 1); break; }
                ++started;
            }
            join();
            if (ah_token_restore_failures != token_failures_before) { InterlockedExchange(&failed, 1); failure_code = ERROR_CANNOT_IMPERSONATE; }
            if (!InterlockedCompareExchange(&failed, 0, 0)) merge();
        }
        ah_host_diagnostics = diagnostics;
        if (ah_token_restore_failures != token_failures_before) { InterlockedExchange(&failed, 1); failure_code = ERROR_CANNOT_IMPERSONATE; }
        if (failed) { if (!failure_code) failure_code = ERROR_GEN_FAILURE; return false; }
        return !control.failed && !source.arena.failed;
    }
    DWORD error() const { return failure_code; }
    unsigned int thread_count() const { return started; }
    size_t window_capacity() const { return capacity; }
    size_t task_memory_bytes() const { return capacity * sizeof(task); }
    ah_host_pool(const ah_host_pool &) = delete;
    ah_host_pool &operator=(const ah_host_pool &) = delete;
};
