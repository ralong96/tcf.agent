/*******************************************************************************
 * Copyright (c) 2010, 2015 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

#include <tcf/config.h>

#if (defined(_WIN32) || defined(__CYGWIN__)) && !defined(DISABLE_PTHREADS_WIN32)

#include <assert.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/errors.h>
#include <system/Windows/tcf/pthreads-win32.h>

#ifndef ENABLE_WindowsUserspaceSynchronization
#  define ENABLE_WindowsUserspaceSynchronization 1
#endif

typedef struct {
    clockid_t clock_id;
} PThreadCondAttr;

int pthread_condattr_init(pthread_condattr_t * attr) {
    PThreadCondAttr * a = (PThreadCondAttr *)loc_alloc_zero(sizeof(PThreadCondAttr));
    a->clock_id = CLOCK_REALTIME;
    *attr = (pthread_condattr_t)a;
    return 0;
}

int pthread_condattr_setclock(pthread_condattr_t * attr, clockid_t clock_id) {
    PThreadCondAttr * a = (PThreadCondAttr *)*attr;
    a->clock_id = clock_id;
    return 0;
}

int pthread_condattr_destroy(pthread_condattr_t * attr) {
    PThreadCondAttr * a = (PThreadCondAttr *)*attr;
    loc_free(a);
    *attr = NULL;
    return 0;
}

#if ENABLE_WindowsUserspaceSynchronization

/*
 * Windows userspace implementation of thread synchronization is much faster.
 * However, it is not available on Windows XP and older version of the OS.
 * So, we have to check OS version and fall back to old APIs when necessary.
 */

static int kernel_version = 0;
static HMODULE kernel_module = NULL;

static int get_kernel_version(void) {
    kernel_version = 1;
    kernel_module = GetModuleHandle("kernel32.dll");
    if (kernel_module != NULL) {
        OSVERSIONINFOEX info;
        memset(&info, 0, sizeof(info));
        info.dwOSVersionInfoSize = sizeof(info);
        if (GetVersionEx((OSVERSIONINFO *)&info)) {
            kernel_version = info.dwMajorVersion;
        }
    }
    return kernel_version;
}

#define use_old_api() (kernel_version ? kernel_version : get_kernel_version()) < 6

extern int windows_mutex_init(pthread_mutex_t * mutex, const pthread_mutexattr_t * attr);
extern int windows_mutex_lock(pthread_mutex_t * mutex);
extern int windows_mutex_unlock(pthread_mutex_t * mutex);
extern int windows_mutex_destroy(pthread_mutex_t *mutex);
extern int windows_cond_init(pthread_cond_t * cond, const pthread_condattr_t * attr);
extern int windows_cond_signal(pthread_cond_t * cond);
extern int windows_cond_broadcast(pthread_cond_t * cond);
extern int windows_cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex);
extern int windows_cond_timedwait(pthread_cond_t * cond, pthread_mutex_t * mutex, const struct timespec * abstime);
extern int windows_cond_destroy(pthread_cond_t * cond);

typedef struct {
    void * var; /* Actual type is CONDITION_VARIABLE, but the type is not defined in Msys */
    clockid_t clock_id;
} PThreadUserspaceCond;

int pthread_mutex_init(pthread_mutex_t * mutex, const pthread_mutexattr_t * attr) {
    typedef void WINAPI ProcType(void *);
    static ProcType * proc = NULL;
    if (proc == NULL) {
        if (use_old_api()) return windows_mutex_init(mutex, attr);
        proc = (ProcType *)GetProcAddress(kernel_module, "InitializeSRWLock");
    }
    proc(mutex);
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t * mutex) {
    typedef void WINAPI ProcType(void *);
    static ProcType * proc = NULL;
    if (proc == NULL) {
        if (use_old_api()) return windows_mutex_lock(mutex);
        proc = (ProcType *)GetProcAddress(kernel_module, "AcquireSRWLockExclusive");
    }
    proc(mutex);
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t * mutex) {
    typedef void WINAPI ProcType(void *);
    static ProcType * proc = NULL;
    if (proc == NULL) {
        if (use_old_api()) return windows_mutex_unlock(mutex);
        proc = (ProcType *)GetProcAddress(kernel_module, "ReleaseSRWLockExclusive");
    }
    proc(mutex);
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t * mutex) {
    if (use_old_api()) return windows_mutex_destroy(mutex);
    *mutex = NULL;
    return 0;
}

int pthread_cond_init(pthread_cond_t * cond, const pthread_condattr_t * attr) {
    PThreadUserspaceCond * p = NULL;
    typedef void WINAPI ProcType(void *);
    static ProcType * proc = NULL;
    if (proc == NULL) {
        if (use_old_api()) return windows_cond_init(cond, attr);
        proc = (ProcType *)GetProcAddress(kernel_module, "InitializeConditionVariable");
    }
    p = (PThreadUserspaceCond *)loc_alloc_zero(sizeof(PThreadUserspaceCond));
    if (attr != NULL) {
        PThreadCondAttr * a = (PThreadCondAttr *)*attr;
        p->clock_id = a->clock_id;
    }
    else {
        p->clock_id = CLOCK_REALTIME;
    }
    *cond = (pthread_cond_t)p;
    proc(&p->var);
    return 0;
}

int pthread_cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex) {
    PThreadUserspaceCond * p = NULL;
    typedef BOOL WINAPI ProcType(void *, void *, DWORD, ULONG);
    static ProcType * proc = NULL;
    if (proc == NULL) {
        if (use_old_api()) return windows_cond_wait(cond, mutex);
        proc = (ProcType *)GetProcAddress(kernel_module, "SleepConditionVariableSRW");
    }
    p = (PThreadUserspaceCond *)*cond;
    return proc(&p->var, mutex, INFINITE, 0) ? 0 : ETIMEDOUT;
}

int pthread_cond_timedwait(pthread_cond_t * cond, pthread_mutex_t * mutex, const struct timespec * abstime) {
    uint64_t t0, t1;
    PThreadUserspaceCond * p = NULL;
    typedef BOOL WINAPI ProcType(void *, void *, DWORD, ULONG);
    typedef ULONGLONG WINAPI ClockProcType(void);
    static ProcType * proc = NULL;
    static ClockProcType * clock_proc = NULL;
    FILETIME ft;
    if (proc == NULL) {
        if (use_old_api()) return windows_cond_timedwait(cond, mutex, abstime);
        proc = (ProcType *)GetProcAddress(kernel_module, "SleepConditionVariableSRW");
        clock_proc = (ClockProcType *)GetProcAddress(kernel_module, "GetTickCount64");
    }
    p = (PThreadUserspaceCond *)*cond;
    if (p->clock_id == CLOCK_MONOTONIC) {
        t0 = clock_proc();
    }
    else if (p->clock_id == CLOCK_REALTIME) {
        GetSystemTimeAsFileTime(&ft);
        t0 = (uint64_t)ft.dwHighDateTime << 32;
        t0 |= ft.dwLowDateTime;
        t0 /= 10000u;            /* from 100 nano-sec periods to msec */
        t0 -= 11644473600000ull; /* from Win epoch to Unix epoch */
    }
    else {
        return ERR_UNSUPPORTED;
    }
    t1 = (uint64_t)abstime->tv_sec * 1000 + (abstime->tv_nsec + 999999) / 1000000;
    if (t1 > t0) return proc(&p->var, mutex, (DWORD)(t1 - t0), 0) ? 0 : ETIMEDOUT;
    return ETIMEDOUT;
}

int pthread_cond_signal(pthread_cond_t * cond) {
    PThreadUserspaceCond * p = NULL;
    typedef void WINAPI ProcType(void *);
    static ProcType * proc = NULL;
    if (proc == NULL) {
        if (use_old_api()) return windows_cond_signal(cond);
        proc = (ProcType *)GetProcAddress(kernel_module, "WakeConditionVariable");
    }
    p = (PThreadUserspaceCond *)*cond;
    proc(&p->var);
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t * cond) {
    PThreadUserspaceCond * p = NULL;
    typedef void WINAPI ProcType(void *);
    static ProcType * proc = NULL;
    if (proc == NULL) {
        if (use_old_api()) return windows_cond_broadcast(cond);
        proc = (ProcType *)GetProcAddress(kernel_module, "WakeAllConditionVariable");
    }
    p = (PThreadUserspaceCond *)*cond;
    proc(&p->var);
    return 0;
}

int pthread_cond_destroy(pthread_cond_t * cond) {
    PThreadUserspaceCond * p = NULL;
    if (use_old_api()) return windows_cond_destroy(cond);
    p = (PThreadUserspaceCond *)*cond;
    loc_free(p);
    *cond = NULL;
    return 0;
}

#define pthread_mutex_init      windows_mutex_init
#define pthread_mutex_lock      windows_mutex_lock
#define pthread_mutex_unlock    windows_mutex_unlock
#define pthread_mutex_destroy   windows_mutex_destroy
#define pthread_cond_init       windows_cond_init
#define pthread_cond_wait       windows_cond_wait
#define pthread_cond_timedwait  windows_cond_timedwait
#define pthread_cond_signal     windows_cond_signal
#define pthread_cond_broadcast  windows_cond_broadcast
#define pthread_cond_destroy    windows_cond_destroy

#endif /* ENABLE_WindowsUserspaceSynchronization */

/*********************************************************************
    Support of pthreads on Windows is implemented according to
    recommendations from the paper:

    Strategies for Implementing POSIX Condition Variables on Win32
    C++ Report, SIGS, Vol. 10, No. 5, June, 1998

    Douglas C. Schmidt and Irfan Pyarali
    Department of Computer Science
    Washington University, St. Louis, Missouri
**********************************************************************/

/* TODO: POSIX pthread functions don't set errno */

typedef struct {
    int waiters_count;
    CRITICAL_SECTION waiters_count_lock;
    HANDLE sema;
    HANDLE waiters_done;
    size_t was_broadcast;
    clockid_t clock_id;
} PThreadCond;

int pthread_mutex_init(pthread_mutex_t * mutex, const pthread_mutexattr_t * attr) {
    assert(attr == NULL);
    *mutex = (pthread_mutex_t)CreateMutex(NULL, FALSE, NULL);
    if (*mutex == NULL) return set_win32_errno(GetLastError());
    return 0;
}

int pthread_mutex_lock(pthread_mutex_t * mutex) {
    assert(mutex != NULL);
    assert(*mutex != NULL);
    if (WaitForSingleObject(*mutex, INFINITE) == WAIT_FAILED) return set_win32_errno(GetLastError());
    return 0;
}

int pthread_mutex_unlock(pthread_mutex_t * mutex) {
    assert(mutex != NULL);
    assert(*mutex != NULL);
    if (!ReleaseMutex(*mutex)) return set_win32_errno(GetLastError());
    return 0;
}

int pthread_mutex_destroy(pthread_mutex_t * mutex) {
    assert(mutex != NULL);
    assert(*mutex != NULL);
    if (!CloseHandle(*mutex)) return set_win32_errno(GetLastError());
    return 0;
}

int pthread_cond_init(pthread_cond_t * cond, const pthread_condattr_t * attr) {
    PThreadCond * p = (PThreadCond *)loc_alloc_zero(sizeof(PThreadCond));
    if (attr != NULL) {
        PThreadCondAttr * a = (PThreadCondAttr *)*attr;
        p->clock_id = a->clock_id;
    }
    else {
        p->clock_id = CLOCK_REALTIME;
    }
    p->waiters_count = 0;
    p->was_broadcast = 0;
    p->sema = CreateSemaphore(NULL, 0, 0x7fffffff, NULL);
    if (p->sema == NULL) return set_win32_errno(GetLastError());
    InitializeCriticalSection(&p->waiters_count_lock);
    p->waiters_done = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (p->waiters_done == NULL) return set_win32_errno(GetLastError());
    *cond = (pthread_cond_t)p;
    return 0;
}

int pthread_cond_wait(pthread_cond_t * cond, pthread_mutex_t * mutex) {
    DWORD res = 0;
    int last_waiter = 0;
    PThreadCond * p = (PThreadCond *)*cond;

    EnterCriticalSection(&p->waiters_count_lock);
    p->waiters_count++;
    LeaveCriticalSection(&p->waiters_count_lock);

    /* This call atomically releases the mutex and waits on the */
    /* semaphore until <pthread_cond_signal> or <pthread_cond_broadcast> */
    /* are called by another thread. */
    res = SignalObjectAndWait(*mutex, p->sema, INFINITE, FALSE);
    if (res == WAIT_FAILED) return set_win32_errno(GetLastError());

    /* Re-acquire lock to avoid race conditions. */
    EnterCriticalSection(&p->waiters_count_lock);

    /* We're no longer waiting... */
    p->waiters_count--;

    /* Check to see if we're the last waiter after <pthread_cond_broadcast>. */
    last_waiter = p->was_broadcast && p->waiters_count == 0;

    LeaveCriticalSection(&p->waiters_count_lock);

    /* If we're the last waiter thread during this particular broadcast */
    /* then let all the other threads proceed. */
    if (last_waiter) {
        /* This call atomically signals the <waiters_done_> event and waits until */
        /* it can acquire the <mutex>.  This is required to ensure fairness.  */
        DWORD err = SignalObjectAndWait(p->waiters_done, *mutex, INFINITE, FALSE);
        if (err == WAIT_FAILED) return set_win32_errno(GetLastError());
    }
    else {
        /* Always regain the external mutex since that's the guarantee we */
        /* give to our callers.  */
        DWORD err = WaitForSingleObject(*mutex, INFINITE);
        if (err == WAIT_FAILED) return set_win32_errno(GetLastError());
    }
    assert(res == WAIT_OBJECT_0);
    return 0;
}

int pthread_cond_timedwait(pthread_cond_t * cond, pthread_mutex_t * mutex, const struct timespec * abstime) {
    DWORD res = 0;
    int last_waiter = 0;
    PThreadCond * p = (PThreadCond *)*cond;
    DWORD timeout = 0;
    struct timespec timenow;

    if (clock_gettime(p->clock_id, &timenow)) return errno;
    if (abstime->tv_sec < timenow.tv_sec) return ETIMEDOUT;
    if (abstime->tv_sec == timenow.tv_sec) {
        if (abstime->tv_nsec <= timenow.tv_nsec) return ETIMEDOUT;
    }
    timeout = (DWORD)((abstime->tv_sec - timenow.tv_sec) * 1000 + (abstime->tv_nsec - timenow.tv_nsec) / 1000000 + 5);

    EnterCriticalSection(&p->waiters_count_lock);
    p->waiters_count++;
    LeaveCriticalSection(&p->waiters_count_lock);

    /* This call atomically releases the mutex and waits on the */
    /* semaphore until <pthread_cond_signal> or <pthread_cond_broadcast> */
    /* are called by another thread. */
    res = SignalObjectAndWait(*mutex, p->sema, timeout, FALSE);
    if (res == WAIT_FAILED) return set_win32_errno(GetLastError());

    /* Re-acquire lock to avoid race conditions. */
    EnterCriticalSection(&p->waiters_count_lock);

    /* We're no longer waiting... */
    p->waiters_count--;

    /* Check to see if we're the last waiter after <pthread_cond_broadcast>. */
    last_waiter = p->was_broadcast && p->waiters_count == 0;

    LeaveCriticalSection(&p->waiters_count_lock);

    /* If we're the last waiter thread during this particular broadcast */
    /* then let all the other threads proceed. */
    if (last_waiter) {
        /* This call atomically signals the <waiters_done> event and waits until */
        /* it can acquire the <mutex>.  This is required to ensure fairness.  */
        DWORD err = SignalObjectAndWait(p->waiters_done, *mutex, INFINITE, FALSE);
        if (err == WAIT_FAILED) return set_win32_errno(GetLastError());
    }
    else {
        /* Always regain the external mutex since that's the guarantee we */
        /* give to our callers.  */
        DWORD err = WaitForSingleObject(*mutex, INFINITE);
        if (err == WAIT_FAILED) return set_win32_errno(GetLastError());
    }

    if (res == WAIT_TIMEOUT) return errno = ETIMEDOUT;
    assert(res == WAIT_OBJECT_0);
    return 0;
}

int pthread_cond_signal(pthread_cond_t * cond) {
    int have_waiters = 0;
    PThreadCond * p = (PThreadCond *)*cond;

    EnterCriticalSection(&p->waiters_count_lock);
    have_waiters = p->waiters_count > 0;
    LeaveCriticalSection(&p->waiters_count_lock);

    /* If there aren't any waiters, then this is a no-op.   */
    if (have_waiters) {
        if (!ReleaseSemaphore(p->sema, 1, 0)) return set_win32_errno(GetLastError());
    }
    return 0;
}

int pthread_cond_broadcast(pthread_cond_t * cond) {
    int have_waiters = 0;
    PThreadCond * p = (PThreadCond *)*cond;

    /* This is needed to ensure that <waiters_count_> and <was_broadcast_> are */
    /* consistent relative to each other. */
    EnterCriticalSection(&p->waiters_count_lock);

    if (p->waiters_count > 0) {
        /* We are broadcasting, even if there is just one waiter... */
        /* Record that we are broadcasting, which helps optimize */
        /* <pthread_cond_wait> for the non-broadcast case. */
        p->was_broadcast = 1;
        have_waiters = 1;
    }

    if (have_waiters) {
        /* Wake up all the waiters atomically. */
        if (!ReleaseSemaphore(p->sema, p->waiters_count, 0)) return set_win32_errno(GetLastError());

        LeaveCriticalSection(&p->waiters_count_lock);

        /* Wait for all the awakened threads to acquire the counting */
        /* semaphore.  */
        if (WaitForSingleObject(p->waiters_done, INFINITE) == WAIT_FAILED) return set_win32_errno(GetLastError());
        /* This assignment is okay, even without the <waiters_count_lock_> held  */
        /* because no other waiter threads can wake up to access it. */
        p->was_broadcast = 0;
    }
    else {
        LeaveCriticalSection(&p->waiters_count_lock);
    }
    return 0;
}

int pthread_cond_destroy(pthread_cond_t * cond) {
    PThreadCond * p = (PThreadCond *)*cond;

    DeleteCriticalSection(&p->waiters_count_lock);
    if (!CloseHandle(p->sema)) return set_win32_errno(GetLastError());
    if (!CloseHandle(p->waiters_done)) return set_win32_errno(GetLastError());

    loc_free(p);
    *cond = NULL;
    return 0;
}

typedef struct ThreadArgs ThreadArgs;

struct ThreadArgs {
    void * (*start)(void *);
    void * args;
};

static void start_thread(void * x) {
    ThreadArgs a = *(ThreadArgs *)x;

    loc_free(x);
    ExitThread((DWORD)(uintptr_t)a.start(a.args));
}

int pthread_create(pthread_t * res, const pthread_attr_t * attr,
                   void * (*start)(void *), void * args) {
    HANDLE thread = NULL;
    DWORD thread_id = 0;
    ThreadArgs * a = (ThreadArgs *)loc_alloc(sizeof(ThreadArgs));

    a->start = start;
    a->args = args;
    thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)start_thread, a, 0, &thread_id);
    if (thread == NULL) {
        int err = set_win32_errno(GetLastError());
        loc_free(a);
        return errno = err;
    }
    if (!CloseHandle(thread)) return set_win32_errno(GetLastError());
    *res = (pthread_t)(uintptr_t)thread_id;
    return 0;
}

int pthread_join(pthread_t thread_id, void ** value_ptr) {
    int error = 0;
    HANDLE thread = OpenThread(SYNCHRONIZE | THREAD_QUERY_INFORMATION, FALSE, (DWORD)(uintptr_t)thread_id);

    if (thread == NULL) return set_win32_errno(GetLastError());
    if (WaitForSingleObject(thread, INFINITE) == WAIT_FAILED) error = set_win32_errno(GetLastError());
    if (!error && value_ptr != NULL && !GetExitCodeThread(thread, (LPDWORD)value_ptr)) error = set_win32_errno(GetLastError());
    if (!CloseHandle(thread) && !error) error = set_win32_errno(GetLastError());
    return error;
}

int pthread_detach(pthread_t thread_id) {
    return 0;
}

pthread_t pthread_self(void) {
    return (pthread_t)(uintptr_t)GetCurrentThreadId();
}

int pthread_equal(pthread_t thread1, pthread_t thread2) {
    return thread1 == thread2;
}

int pthread_attr_init(pthread_attr_t * attr) {
    *attr = NULL;
    return 0;
}

#endif
