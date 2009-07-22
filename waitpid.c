/*******************************************************************************
 * Copyright (c) 2009 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials 
 * are made available under the terms of the Eclipse Public License v1.0 
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *  
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * This module provides notifications of process/thread exited or stopped.
 */

#include "config.h"

#if ENABLE_DebugContext || SERVICE_Processes

#include <assert.h>
#include <errno.h>
#include "errors.h"
#include "myalloc.h"
#include "events.h"
#include "trace.h"
#include "waitpid.h"

typedef struct WaitPIDListenerInfo {
    WaitPIDListener * listener;
    void * args;
} WaitPIDListenerInfo;

#define MAX_LISTENERS 8

static WaitPIDListenerInfo listeners[MAX_LISTENERS];
static int listener_cnt = 0;

static void init(void);

void add_waitpid_listener(WaitPIDListener * listener, void * args) {
    assert(listener_cnt < MAX_LISTENERS);
    if (listener_cnt == 0) init();
    listeners[listener_cnt].listener = listener;
    listeners[listener_cnt].args = args;
    listener_cnt++;
}

#if defined(WIN32)

#define MAX_HANDLES 64

typedef struct WaitPIDThread {
    DWORD thread;
    HANDLE handles[MAX_HANDLES];
    DWORD handle_cnt;
    struct WaitPIDThread * next;
} WaitPIDThread;

static WaitPIDThread * threads = NULL;
static HANDLE semaphore = NULL;

#define check_error_win32(ok) { if (!(ok)) check_error(set_win32_errno(GetLastError())); }

static void waitpid_event(void * args) {
    int i;
    HANDLE prs = args;
    DWORD pid = GetProcessId(prs);
    DWORD exit_code = 0;
    check_error_win32(GetExitCodeProcess(prs, &exit_code));
    for (i = 0; i < listener_cnt; i++) {
        listeners[i].listener(pid, 1, exit_code, 0, 0, 0, listeners[i].args);
    }
    check_error_win32(CloseHandle(prs));
}

static DWORD WINAPI waitpid_thread_func(LPVOID x) {
    WaitPIDThread * thread = x;
    check_error_win32(WaitForSingleObject(semaphore, INFINITE) != WAIT_FAILED);
    for (;;) {
        DWORD n = 0;
        HANDLE arr[MAX_HANDLES];
        DWORD cnt = thread->handle_cnt;
        memcpy(arr, thread->handles, cnt * sizeof(HANDLE));
        check_error_win32(ReleaseSemaphore(semaphore, 1, 0));
        n = WaitForMultipleObjects(cnt, arr, FALSE, INFINITE);
        check_error_win32(n != WAIT_FAILED);
        check_error_win32(WaitForSingleObject(semaphore, INFINITE) != WAIT_FAILED);
        if (n > 0) {
            assert(thread->handles[n] == arr[n]);
            post_event(waitpid_event, thread->handles[n]);
            memmove(thread->handles + n, thread->handles + n + 1, (thread->handle_cnt - n - 1) * sizeof(HANDLE));
            thread->handle_cnt--;
        }
    }
}

static void init(void) {
    assert(threads == NULL);
    semaphore = CreateSemaphore(NULL, 1, 1, NULL);
}

void add_waitpid_process(int pid) {
    HANDLE prs = NULL;
    WaitPIDThread * thread = threads;
    check_error_win32(WaitForSingleObject(semaphore, INFINITE) != WAIT_FAILED);
    while (thread != NULL && thread->handle_cnt >= MAX_HANDLES) thread = thread->next;
    if (thread == NULL) {
        thread = loc_alloc_zero(sizeof(WaitPIDThread));
        thread->next = threads;
        threads = thread;
        check_error_win32((thread->handles[thread->handle_cnt++] = CreateSemaphore(NULL, 0, 1, NULL)) != NULL);
        check_error_win32(CreateThread(NULL, 0, waitpid_thread_func, thread, 0, &thread->thread) != NULL);
    }
    check_error_win32((prs = OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, pid)) != NULL);
    thread->handles[thread->handle_cnt++] = prs;
    check_error_win32(ReleaseSemaphore(thread->handles[0], 1, 0));
    check_error_win32(ReleaseSemaphore(semaphore, 1, 0));
}

#elif defined(_WRS_KERNEL)

#include <taskHookLib.h>

typedef struct EventInfo {
    UINT32 pid;
    SEM_ID signal;
} EventInfo;

static WIND_TCB * main_thread;

static void task_delete_event(void * args) {
    int i;
    EventInfo * info = args;
    for (i = 0; i < listener_cnt; i++) {
        listeners[i].listener(info->pid, 1, 0, 0, 0, 0, listeners[i].args);
    }
    semGive(info->signal);
}

static void task_delete_hook(WIND_TCB * tcb) {
    if (tcb != main_thread && taskIdCurrent != main_thread) {
        EventInfo info;
        VX_COUNTING_SEMAPHORE(signal_mem);
        info.signal = semCInitialize(signal_mem, SEM_Q_FIFO, 0);
        info.pid = (UINT32)tcb;
        post_event(task_delete_event, &info);
        semTake(info.signal, WAIT_FOREVER);
        semTerminate(info.signal);
    }
}

static void init(void) {
    main_thread = taskIdCurrent;
    taskDeleteHookAdd((FUNCPTR)task_delete_hook);
}

void add_waitpid_process(int pid) {
}

#else

#include <sys/wait.h>

typedef struct EventInfo {
    int pid;
    int exited;
    int exit_code;
    int signal;
    int event_code;
    int syscall;
} EventInfo;

static int waitpid_poll_rate;
static pthread_mutex_t waitpid_lock;
static pthread_cond_t waitpid_cond;
static pthread_t waitpid_thread;

static void waitpid_event(void * args) {
    int i;
    EventInfo * info = (EventInfo *)args;
    for (i = 0; i < listener_cnt; i++) {
        listeners[i].listener(info->pid, info->exited, info->exit_code, info->signal, info->event_code, info->syscall, listeners[i].args);
    }
    loc_free(info);
}

static void * wpid_handler(void * x) {
    for (;;) {
        pid_t pid;
        int err;
        int status;
        EventInfo * info;
        /* TODO: use AsyncReqWaitpid instead of calling waitpid() directly */
#if defined(__APPLE__)
        pid = waitpid(-1, &status, 0);
#else
        pid = waitpid(-1, &status, __WALL);
#endif
        if (pid == (pid_t)-1) {
            if (errno == ECHILD) {
                struct timespec timeout;
                check_error(pthread_mutex_lock(&waitpid_lock));
                if (waitpid_poll_rate < 60 * 1000) {
                    waitpid_poll_rate = (waitpid_poll_rate * 3 + 1)/2;
                }
                clock_gettime(CLOCK_REALTIME, &timeout);
                timeout.tv_sec += waitpid_poll_rate / 1000;
                timeout.tv_nsec += (waitpid_poll_rate % 1000) * 1000 * 1000;
                if (timeout.tv_nsec >= 1000 * 1000 * 1000) {
                    timeout.tv_nsec -= 1000 * 1000 * 1000;
                    timeout.tv_sec++;
                }
                err = pthread_cond_timedwait(&waitpid_cond, &waitpid_lock, &timeout);
                if (err != ETIMEDOUT) check_error(err);
                check_error(pthread_mutex_unlock(&waitpid_lock));
                continue;
            }
            check_error(errno);
        }
        trace(LOG_WAITPID, "waitpid: pid %d status %#x", pid, status);
        info = loc_alloc_zero(sizeof(EventInfo));
        info->pid = pid;
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            info->exited = 1;
            if (WIFEXITED(status)) info->exit_code = WEXITSTATUS(status);
            else info->signal = WTERMSIG(status);
            post_event(waitpid_event, info);
        }
        else if (WIFSTOPPED(status)) {
            info->signal = WSTOPSIG(status) & 0x7f;
            info->syscall = (WSTOPSIG(status) & 0x80) != 0;
            info->event_code = status >> 16;
            post_event(waitpid_event, info);
        }
        else {
            trace(LOG_ALWAYS, "unexpected status (0x%x) from waitpid (pid %d)", status, pid);
            loc_free(info);
        }
    }
    return NULL;
}

static void init(void) {
    waitpid_poll_rate = 1;
    check_error(pthread_mutex_init(&waitpid_lock, NULL));
    check_error(pthread_cond_init(&waitpid_cond, NULL));
    check_error(pthread_create(&waitpid_thread, &pthread_create_attr, wpid_handler, NULL));
}

void add_waitpid_process(int pid) {
    assert(listener_cnt > 0);
    check_error(pthread_mutex_lock(&waitpid_lock));
    trace(LOG_WAITPID, "waitpid: poll rate reset");
    waitpid_poll_rate = 1;
    check_error(pthread_cond_signal(&waitpid_cond));
    check_error(pthread_mutex_unlock(&waitpid_lock));
}

#endif
#endif
