#pragma once
#include <new>

class ah_object_pool final {
public:
    using selected_fn = bool (*)(ah_graph &, const ah_object *);
    using transform_fn = bool (*)(ah_graph &, ah_object *, ah_buffer &);
    using sink_fn = bool (*)(void *, const ah_object *, const ah_buffer &, ah_graph &);
private:
    using create_fn = HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using event_fn = HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
    using signal_fn = BOOL (WINAPI *)(HANDLE);
    using wait_fn = DWORD (WINAPI *)(HANDLE, DWORD);
    using exit_fn = BOOL (WINAPI *)(HANDLE, LPDWORD);
    using open_token_fn = BOOL (WINAPI *)(HANDLE, DWORD, BOOL, PHANDLE);
    using set_token_fn = BOOL (WINAPI *)(PHANDLE, HANDLE);

    struct context final {
        ah_directory directory;
        ah_graph graph;
        ah_object object;
        ah_buffer json;
        context(size_t limit, bool ad, const ah_object &original)
            : directory(limit, 4096), graph(directory, ad), object(original), json(limit, 4096) {}
    };
    struct task { ah_object *original; context *result; volatile LONG completed; };
    struct worker final {
        ah_object_pool &pool;
        worker *next = nullptr;
        HANDLE wake = nullptr, done = nullptr, thread = nullptr;
        void *directory_runtime = nullptr;
        explicit worker(ah_object_pool &owner) : pool(owner) {}
    };

    ah_graph &source;
    size_t maximum;
    const char *forest = nullptr;
    ah_native_library kernel, advapi;
    worker *workers = nullptr;
    task *tasks = nullptr;
    size_t capacity = 0, count = 0;
    HANDLE token = nullptr, progress = nullptr;
    create_fn create = nullptr;
    event_fn event = nullptr;
    signal_fn signal = nullptr, reset = nullptr;
    wait_fn wait = nullptr;
    exit_fn exit_code = nullptr;
    set_token_fn set_token = nullptr;
    transform_fn transform = nullptr;
    volatile LONG cursor = -1, failed = 0, stopping = 0, failure_code = ERROR_SUCCESS;
    LONG token_failures_before = 0;
    unsigned int started = 0;
    bool used = false;

    void fail(DWORD code) {
        if (!code) code = ERROR_GEN_FAILURE;
        InterlockedCompareExchange(&failure_code, static_cast<LONG>(code), ERROR_SUCCESS);
        InterlockedExchange(&failed, 1);
    }
    bool prepare(context &state) {
        ah_graph &g = state.graph;
        state.directory.objects = source.directory.objects;
        state.directory.count = source.directory.count;
        g.dns = source.dns.read_only_view(g.arena);
        g.sids = source.sids.read_only_view(g.arena);
        g.hosts = source.hosts.read_only_view(g.arena);
        g.accounts = source.accounts.read_only_view(g.arena);
        g.principals = source.principals.read_only_view(g.arena);
        g.root = source.root; g.domain = source.domain; g.forest_name = forest;
        g.laps_guid = source.laps_guid; g.laps_guid_v2 = source.laps_guid_v2; g.laps_guid_v3 = source.laps_guid_v3;
        g.domain_names = source.domain_names;
        g.sid_kind_cache = source.sid_kind_cache;
        g.gpo_cache = source.gpo_cache;
        g.gpo_index_ready = source.gpo_index_ready;
        g.computer_filter = source.computer_filter;
        g.selected_computers = source.selected_computers;
        g.stealth_targets = source.stealth_targets;
        g.stealth_targets_built = source.stealth_targets_built;
        g.parallel_worker = true;
        return !g.arena.failed;
    }
    bool process(task &item, void *directory_runtime) {
        context *state = ah_alloc<context>(sizeof(context));
        if (!state) { fail(ERROR_NOT_ENOUGH_MEMORY); return false; }
        new (state) context(maximum, source.ad, *item.original);
        item.result = state;
        if (!prepare(*state)) { fail(ERROR_NOT_ENOUGH_MEMORY); return false; }
        state->graph.directory_runtime = directory_runtime ? directory_runtime : source.directory_runtime;
        if (!transform(state->graph, &state->object, state->json)) {
            fail(state->graph.arena.failed || state->json.failed ? ERROR_NOT_ENOUGH_MEMORY : ERROR_GEN_FAILURE);
            return false;
        }
        if (state->graph.arena.failed || state->json.failed) { fail(ERROR_NOT_ENOUGH_MEMORY); return false; }
        if (ah_token_restore_failures != token_failures_before) { fail(ERROR_CANNOT_IMPERSONATE); return false; }
        return true;
    }
    static DWORD WINAPI work(void *parameter) {
        worker &state = *static_cast<worker *>(parameter);
        ah_object_pool &pool = state.pool;
        bool impersonated = false, directory_initialized = false;
        for (;;) {

            DWORD status = pool.wait(state.wake, 50);
            if (InterlockedCompareExchange(&pool.stopping, 0, 0)) break;
            if (status == WAIT_TIMEOUT) continue;
            if (status != WAIT_OBJECT_0) { pool.fail(KERNEL32$GetLastError()); break; }
            if (InterlockedCompareExchange(&pool.failed, 0, 0)) break;
            if (pool.token && !impersonated) {
                if (!pool.set_token(nullptr, pool.token)) { pool.fail(KERNEL32$GetLastError()); break; }
                impersonated = true;
            }
            if (!directory_initialized) {
                if (ah_worker_directory_runtime_required()) {
                    state.directory_runtime = ah_create_worker_directory_runtime();
                    if (!state.directory_runtime) { pool.fail(ERROR_NOT_ENOUGH_MEMORY); break; }
                }
                directory_initialized = true;
            }
            for (;;) {
                if (InterlockedCompareExchange(&pool.failed, 0, 0) || InterlockedCompareExchange(&pool.stopping, 0, 0)) break;
                LONG index = InterlockedIncrement(&pool.cursor);
                if (index < 0 || static_cast<size_t>(index) >= pool.count) break;
                task &item = pool.tasks[index];
                if (!pool.process(item, state.directory_runtime)) break;
                InterlockedExchange(&item.completed, 1);
                if (!pool.signal(pool.progress)) { pool.fail(KERNEL32$GetLastError()); break; }
            }
            if (!pool.signal(state.done)) { pool.fail(KERNEL32$GetLastError()); break; }
        }
        if (state.directory_runtime) {
            ah_destroy_worker_directory_runtime(state.directory_runtime); state.directory_runtime = nullptr;
        }
        if (impersonated && !pool.set_token(nullptr, nullptr)) pool.fail(ERROR_CANNOT_IMPERSONATE);
        return InterlockedCompareExchange(&pool.failed, 0, 0) ? ERROR_GEN_FAILURE : ERROR_SUCCESS;
    }
    void shutdown() {
        InterlockedExchange(&stopping, 1);
        for (worker *state = workers; state; state = state->next)
            if (state->thread && !signal(state->wake)) fail(KERNEL32$GetLastError());
        for (worker *state = workers; state; state = state->next) if (state->thread) {

            while (wait(state->thread, 50) != WAIT_OBJECT_0) {
                ah_drain_observability();
                DWORD code = STILL_ACTIVE;
                if (exit_code(state->thread, &code) && code != STILL_ACTIVE) break;
                KERNEL32$Sleep(1);
            }
            DWORD code = ERROR_GEN_FAILURE;
            if (!exit_code(state->thread, &code) || code != ERROR_SUCCESS) fail(code);
            KERNEL32$CloseHandle(state->thread); state->thread = nullptr;
        }
    }
    void release_results() {
        for (size_t i = 0; i < count; ++i) if (tasks[i].result) {
            tasks[i].result->~context(); ah_free(tasks[i].result); tasks[i].result = nullptr;
        }
    }
    bool dispatch() {
        cursor = -1;
        for (worker *state = workers; state; state = state->next) {
            if (!reset(state->done)) { fail(KERNEL32$GetLastError()); return false; }
        }
        for (worker *state = workers; state; state = state->next) {
            if (!signal(state->wake)) { fail(KERNEL32$GetLastError()); return false; }
        }
        return true;
    }
    bool await_workers() {
        for (worker *state = workers; state; state = state->next) for (;;) {
            if (InterlockedCompareExchange(&failed, 0, 0)) return false;
            DWORD status = wait(state->done, 50);
            ah_drain_observability();
            if (status == WAIT_OBJECT_0) break;
            if (status != WAIT_TIMEOUT) { fail(KERNEL32$GetLastError()); return false; }
        }
        return !InterlockedCompareExchange(&failed, 0, 0);
    }
    bool await_result(task &item) {
        for (;;) {
            if (InterlockedCompareExchange(&failed, 0, 0)) return false;
            if (InterlockedCompareExchange(&item.completed, 0, 0)) return true;
            DWORD status = wait(progress, 50);
            ah_drain_observability();
            if (status != WAIT_OBJECT_0 && status != WAIT_TIMEOUT) { fail(KERNEL32$GetLastError()); return false; }
        }
    }
    bool start(unsigned int threads) {
        create = kernel.find<create_fn>("CreateThread"); event = kernel.find<event_fn>("CreateEventW");
        signal = kernel.find<signal_fn>("SetEvent"); reset = kernel.find<signal_fn>("ResetEvent");
        wait = kernel.find<wait_fn>("WaitForSingleObject"); exit_code = kernel.find<exit_fn>("GetExitCodeThread");
        set_token = advapi.find<set_token_fn>("SetThreadToken"); auto open = advapi.find<open_token_fn>("OpenThreadToken");
        if (!create || !event || !signal || !reset || !wait || !exit_code || !set_token || !open) { fail(ERROR_PROC_NOT_FOUND); return false; }
        if (!open(reinterpret_cast<HANDLE>(static_cast<intptr_t>(-2)), TOKEN_QUERY | TOKEN_IMPERSONATE, TRUE, &token) && KERNEL32$GetLastError() != ERROR_NO_TOKEN) {
            fail(KERNEL32$GetLastError()); return false;
        }
        progress = event(nullptr, FALSE, FALSE, nullptr);
        if (!progress) { fail(KERNEL32$GetLastError()); return false; }
        for (unsigned int i = 0; i < threads; ++i) {
            worker *state = ah_alloc<worker>(sizeof(worker));
            if (!state) { fail(ERROR_NOT_ENOUGH_MEMORY); return false; }
            new (state) worker(*this); state->next = workers; workers = state;
            state->wake = event(nullptr, FALSE, FALSE, nullptr);
            state->done = event(nullptr, TRUE, FALSE, nullptr);
            if (!state->wake || !state->done) { fail(KERNEL32$GetLastError()); return false; }
            state->thread = create(nullptr, 0, work, state, 0, nullptr);
            if (!state->thread) { fail(KERNEL32$GetLastError()); return false; }
            ++started;
        }
        return true;
    }
public:
    ah_object_pool(ah_graph &graph, size_t per_object_limit)
        : source(graph), maximum(per_object_limit), kernel(L"kernel32.dll"), advapi(L"advapi32.dll") {}
    ~ah_object_pool() {
        shutdown(); release_results(); ah_free(tasks);
        if (token) KERNEL32$CloseHandle(token);
        if (progress) KERNEL32$CloseHandle(progress);
        while (workers) {
            worker *next = workers->next;
            if (workers->wake) KERNEL32$CloseHandle(workers->wake);
            if (workers->done) KERNEL32$CloseHandle(workers->done);
            workers->~worker(); ah_free(workers); workers = next;
        }
    }
    bool run(ah_object *list, int threads, selected_fn selected, transform_fn convert, sink_fn sink, void *opaque) {
        if (used || threads < 1 || !selected || !convert || !sink) { fail(ERROR_INVALID_PARAMETER); return false; }
        used = true; transform = convert; token_failures_before = ah_token_restore_failures;
        size_t total = 0;
        for (ah_object *object = list; object; object = object->next) if (selected(source, object)) {
            if (total == SIZE_MAX) { fail(ERROR_ARITHMETIC_OVERFLOW); return false; }
            ++total;
        }
        if (!total) return true;
        forest = source.forest_domain();
        if (source.arena.failed) { fail(ERROR_NOT_ENOUGH_MEMORY); return false; }
        unsigned int concurrency = total < static_cast<size_t>(threads) ? static_cast<unsigned int>(total) : static_cast<unsigned int>(threads);
        capacity = concurrency < 1000 ? 1000 : concurrency;
        if (capacity > total) capacity = total;
        if (capacity > SIZE_MAX / sizeof(task)) { fail(ERROR_ARITHMETIC_OVERFLOW); return false; }
        tasks = ah_alloc<task>(capacity * sizeof(task));
        if (!tasks) { fail(ERROR_NOT_ENOUGH_MEMORY); return false; }
        if (concurrency > 1 && !start(concurrency)) { shutdown(); return false; }
        ah_object *next = list;
        while (next && !InterlockedCompareExchange(&failed, 0, 0)) {
            count = 0;
            while (next && count < capacity) {
                ah_object *object = next; next = next->next;
                if (selected(source, object)) {
                    tasks[count].original = object; tasks[count].result = nullptr; tasks[count++].completed = 0;
                }
            }
            if (!count) continue;
            bool complete = true;
            if (concurrency > 1) complete = dispatch();
            if (!complete) { shutdown(); release_results(); return false; }
            for (size_t i = 0; i < count; ++i) {
                if (concurrency == 1 ? !process(tasks[i], source.directory_runtime) : !await_result(tasks[i])) { complete = false; break; }
                context *state = tasks[i].result;
                if (!state || !sink(opaque, &state->object, state->json, state->graph)) {
                    fail(state && (state->graph.arena.failed || state->json.failed) ? ERROR_NOT_ENOUGH_MEMORY : ERROR_GEN_FAILURE);
                    complete = false; break;
                }
                state->~context(); ah_free(state); tasks[i].result = nullptr;
            }
            if (complete && concurrency > 1) complete = await_workers();
            if (!complete) { shutdown(); release_results(); return false; }
        }
        shutdown();
        if (ah_token_restore_failures != token_failures_before) fail(ERROR_CANNOT_IMPERSONATE);
        return !InterlockedCompareExchange(&failed, 0, 0);
    }
    DWORD error() const { return static_cast<DWORD>(failure_code); }
    unsigned int thread_count() const { return started; }
    size_t window_capacity() const { return capacity; }
    ah_object_pool(const ah_object_pool &) = delete;
    ah_object_pool &operator=(const ah_object_pool &) = delete;
};
