/*
 * Process handle query regression tests.
 *
 * Ported from the local Wine 11.17 handle-regression.c laboratory.
 * These are local regression expectations, not independently measured Windows
 * results (in particular class 58 truncation, access and error precedence).
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/test.h"

static NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, void *, ULONG, ULONG *);
static NTSTATUS (WINAPI *pNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, void *, ULONG, ULONG *);
static BOOL (WINAPI *pGetProcessHandleCount)(HANDLE, DWORD *);

static BOOL contains_handle(const ULONG *table, ULONG count, HANDLE handle)
{
    ULONG i;
    for (i = 0; i < count; ++i)
        if (table[i] == HandleToULong(handle)) return TRUE;
    return FALSE;
}

/* Use an independent server query, not ProcessHandleCount, as the set oracle.
 * The caller and the cooperating child keep their handles stable throughout. */
static ULONG check_snapshot(HANDLE process, DWORD pid, ULONG *table, ULONG capacity)
{
    SYSTEM_HANDLE_INFORMATION_EX *info, *new_info;
    ULONG bytes = 0xdeadbeef, size = 65536, needed, count = 0, matches, j;
    ULONG_PTR i;
    NTSTATUS status;

    status = pNtQueryInformationProcess(process, ProcessHandleTable, table,
                                       capacity * sizeof(*table), &bytes);
    ok(!status, "ProcessHandleTable returned %#lx\n", status);
    ok(!(bytes % sizeof(*table)) && bytes <= capacity * sizeof(*table),
       "Invalid table length %lu\n", bytes);
    if (status || bytes % sizeof(*table) || bytes > capacity * sizeof(*table)) return 0;

    info = malloc(size);
    ok(!!info, "Failed to allocate snapshot\n");
    if (!info) return bytes / sizeof(*table);
    for (;;)
    {
        needed = 0;
        status = pNtQuerySystemInformation(SystemExtendedHandleInformation, info, size, &needed);
        if (status != STATUS_INFO_LENGTH_MISMATCH) break;
        if (size >= 16 * 1024 * 1024 || needed > 16 * 1024 * 1024) break;
        size = max(size * 2, needed);
        new_info = realloc(info, size);
        if (!new_info) break;
        info = new_info;
    }
    ok(!status, "SystemExtendedHandleInformation returned %#lx\n", status);
    if (!status)
    {
        ok(info->NumberOfHandles <= (size - FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles)) /
                                   sizeof(info->Handles[0]), "Invalid system snapshot size\n");
        if (info->NumberOfHandles <= (size - FIELD_OFFSET(SYSTEM_HANDLE_INFORMATION_EX, Handles)) /
                                     sizeof(info->Handles[0]))
        {
            for (i = 0; i < info->NumberOfHandles; ++i)
            {
                if (info->Handles[i].UniqueProcessId != pid) continue;
                ++count;
                matches = 0;
                for (j = 0; j < bytes / sizeof(*table); ++j)
                    matches += table[j] == info->Handles[i].HandleValue;
                ok(matches == 1, "PID %lu handle %#Ix occurs %lu times\n",
                   pid, info->Handles[i].HandleValue, matches);
            }
            ok(count == bytes / sizeof(*table), "PID %lu: system has %lu handles, table has %lu\n",
               pid, count, bytes / (ULONG)sizeof(*table));
        }
    }
    free(info);
    return bytes / sizeof(*table);
}

static void test_access(DWORD pid)
{
    static const DWORD masks[] =
    {
        0, SYNCHRONIZE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_QUERY_INFORMATION,
        PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE,
        PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE
    };
    ULONG table[16384], count, len;
    HANDLE process, source;
    NTSTATUS status, expected;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(masks); ++i)
    {
        winetest_push_context("pid %lu access %#lx", pid, masks[i]);
        process = NULL;
        if (!masks[i])
        {
            /* OpenProcess(0) is rejected by Wine's generic handle allocator;
             * duplicate a valid handle to test a genuinely zero-access handle. */
            source = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid);
            ok(!!source, "OpenProcess failed: %lu\n", GetLastError());
            if (source)
            {
                ok(DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &process,
                                   0, FALSE, 0), "DuplicateHandle failed: %lu\n", GetLastError());
                CloseHandle(source);
            }
        }
        else process = OpenProcess(masks[i], FALSE, pid);
        ok(!!process, "Failed to create process handle: %lu\n", GetLastError());
        if (process)
        {
            expected = masks[i] & (PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION) ?
                       STATUS_SUCCESS : STATUS_ACCESS_DENIED;
            count = len = 0xdeadbeef;
            status = pNtQueryInformationProcess(process, ProcessHandleCount, &count, sizeof(count), &len);
            ok(status == expected, "Count returned %#lx, expected %#lx\n", status, expected);
            expected = (masks[i] & (PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE)) ==
                       (PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
            len = 0xdeadbeef;
            status = pNtQueryInformationProcess(process, ProcessHandleTable, table, sizeof(table), &len);
            ok(status == expected, "Table returned %#lx, expected %#lx\n", status, expected);
            if (!expected) check_snapshot(process, pid, table, ARRAY_SIZE(table));
            /* Recheck a weak handle after the table query: pinning must not upgrade it. */
            len = 0xdeadbeef;
            status = pNtQueryInformationProcess(process, ProcessHandleTable, table, sizeof(table), &len);
            ok(status == expected, "Repeated table query returned %#lx\n", status);
            CloseHandle(process);
        }
        winetest_pop_context();
    }
}

static void test_sizes_and_errors(void)
{
    ULONG table[16384], n, count, len, size, i, j;
    union { ULONG align; BYTE bytes[32]; } buffer;
    ULONG guards[2];
    HANDLE self = GetCurrentProcess(), process, event, invalid[3];
    NTSTATUS status;
    void *blocked;

    n = check_snapshot(self, GetCurrentProcessId(), table, ARRAY_SIZE(table));
    for (size = 0; size < 16; ++size)
    {
        memset(&buffer, 0xa5, sizeof(buffer));
        len = 0xdeadbeef;
        status = pNtQueryInformationProcess(self, ProcessHandleTable, &buffer, size, &len);
        ok(!status, "Size %lu returned %#lx\n", size, status);
        ok(len == min(n, size / sizeof(ULONG)) * sizeof(ULONG),
           "Size %lu returned length %lu\n", size, len);
        if (len <= sizeof(buffer) && !(len % sizeof(ULONG)))
        {
            for (j = len; j < sizeof(buffer); ++j)
                ok(buffer.bytes[j] == 0xa5, "Size %lu overwrote byte %lu\n", size, j);
            for (j = 0; j < len / sizeof(ULONG); ++j)
                ok(contains_handle(table, n, ULongToHandle(((ULONG *)buffer.bytes)[j])),
                   "Truncated table contains unknown handle\n");
        }
    }
    status = pNtQueryInformationProcess(self, ProcessHandleTable, table, sizeof(table), NULL);
    ok(!status, "Optional table length returned %#lx\n", status);
    count = 0xdeadbeef;
    status = pNtQueryInformationProcess(self, ProcessHandleCount, &count, sizeof(count), NULL);
    ok(!status && count == n, "Optional count length: %#lx, count %lu, expected %lu\n", status, count, n);
    len = 0xdeadbeef;
    status = pNtQueryInformationProcess(self, ProcessHandleTable, NULL, sizeof(ULONG), &len);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL table returned %#lx\n", status);
    len = 0xdeadbeef;
    status = pNtQueryInformationProcess(self, ProcessHandleCount, NULL, sizeof(ULONG), &len);
    ok(status == STATUS_ACCESS_VIOLATION, "NULL count returned %#lx\n", status);
    for (size = 0; size < sizeof(ULONG); ++size)
    {
        count = 0xa5a5a5a5;
        len = 0xdeadbeef;
        status = pNtQueryInformationProcess(self, ProcessHandleCount, &count, size, &len);
        ok(status == STATUS_INFO_LENGTH_MISMATCH, "Count size %lu returned %#lx\n", size, status);
        ok(count == 0xa5a5a5a5 && len == sizeof(count), "Count size %lu: %#lx, length %lu\n", size, count, len);
    }
    guards[0] = guards[1] = 0xa5a5a5a5;
    len = 0xdeadbeef;
    status = pNtQueryInformationProcess(self, ProcessHandleCount, guards, sizeof(guards), &len);
    ok(status == STATUS_INFO_LENGTH_MISMATCH, "Oversized count returned %#lx\n", status);
    ok(guards[0] == n && guards[1] == 0xa5a5a5a5 && len == sizeof(ULONG),
       "Oversized count: %lu, guard %#lx, length %lu\n", guards[0], guards[1], len);

    event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ok(!!event, "CreateEvent failed\n");
    invalid[0] = NULL;
    invalid[1] = ULongToHandle(0x12345678);
    invalid[2] = event;
    for (i = 0; i < ARRAY_SIZE(invalid); ++i)
        for (j = 0; j < 2; ++j)
        {
            len = 0xdeadbeef;
            status = pNtQueryInformationProcess(invalid[i], j ? ProcessHandleTable : ProcessHandleCount,
                                               table, j ? sizeof(table) : sizeof(ULONG), &len);
            ok(status == (i == 2 ? STATUS_OBJECT_TYPE_MISMATCH : STATUS_INVALID_HANDLE),
               "Invalid handle %p class %lu returned %#lx\n", invalid[i], j, status);
        }
    CloseHandle(event);

    process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, GetCurrentProcessId());
    blocked = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    ok(!!process && !!blocked, "Failed to prepare inaccessible buffer test\n");
    if (process && blocked)
    {
        n = check_snapshot(self, GetCurrentProcessId(), table, ARRAY_SIZE(table));
        for (i = 0; i < 32; ++i)
            for (j = 0; j < 2; ++j)
            {
                len = 0xdeadbeef;
                status = pNtQueryInformationProcess(process, j ? ProcessHandleTable : ProcessHandleCount,
                                                   blocked, j ? 16 : sizeof(ULONG), &len);
                ok(status == STATUS_ACCESS_VIOLATION, "Inaccessible buffer returned %#lx\n", status);
            }
        count = check_snapshot(self, GetCurrentProcessId(), table, ARRAY_SIZE(table));
        ok(count == n, "Faulting queries leaked handles: %lu -> %lu\n", n, count);
    }
    if (blocked) VirtualFree(blocked, 0, MEM_RELEASE);
    if (process) CloseHandle(process);
}

static void test_own_handles(void)
{
    ULONG table[16384], initial, count, n, len;
    HANDLE events[600], self = GetCurrentProcess();
    unsigned int i, round;
    NTSTATUS status;

    initial = check_snapshot(self, GetCurrentProcessId(), table, ARRAY_SIZE(table));
    ok(initial > 0, "Empty own handle table\n");
    count = len = 0xdeadbeef;
    status = pNtQueryInformationProcess(self, ProcessHandleCount, &count, sizeof(count), &len);
    ok(!status && count == initial && len == sizeof(count),
       "Count returned %#lx, %lu handles, %lu bytes (expected %lu handles)\n", status, count, len, initial);
    for (round = 0; round < 2; ++round)
    {
        for (i = 0; i < ARRAY_SIZE(events); ++i)
        {
            events[i] = CreateEventW(NULL, FALSE, FALSE, NULL);
            ok(!!events[i], "CreateEvent %u failed\n", i);
        }
        n = check_snapshot(self, GetCurrentProcessId(), table, ARRAY_SIZE(table));
        ok(n == initial + ARRAY_SIZE(events), "Got %lu handles, expected %lu\n", n, initial + (ULONG)ARRAY_SIZE(events));
        for (i = 0; i < ARRAY_SIZE(events); ++i)
            ok(contains_handle(table, n, events[i]), "Missing event %p\n", events[i]);
        count = 0xdeadbeef;
        ok(pGetProcessHandleCount(self, &count), "GetProcessHandleCount failed\n");
        ok(count == n, "GetProcessHandleCount returned %lu, expected %lu\n", count, n);
        for (i = 0; i < ARRAY_SIZE(events); ++i)
            if (events[i]) ok(CloseHandle(events[i]), "CloseHandle failed\n");
        n = check_snapshot(self, GetCurrentProcessId(), table, ARRAY_SIZE(table));
        ok(n == initial, "After close: %lu handles, expected %lu\n", n, initial);
        for (i = 0; i < ARRAY_SIZE(events); ++i)
            ok(!contains_handle(table, n, events[i]), "Closed event %p remains\n", events[i]);
    }
}

static void child_process(char **argv)
{
    HANDLE pipe = (HANDLE)(ULONG_PTR)strtoull(argv[3], NULL, 16);
    HANDLE done = (HANDLE)(ULONG_PTR)strtoull(argv[4], NULL, 16);
    HANDLE event = CreateEventW(NULL, FALSE, FALSE, NULL);
    ULONG value = HandleToULong(event);
    DWORD written;

    ok(!!event, "Child CreateEvent failed\n");
    ok(WriteFile(pipe, &value, sizeof(value), &written, NULL) && written == sizeof(value),
       "Child failed to report event\n");
    ok(WaitForSingleObject(done, 20000) == WAIT_OBJECT_0, "Child wait timed out\n");
    if (event) CloseHandle(event);
    CloseHandle(pipe);
    CloseHandle(done);
}

static void test_child(void)
{
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    char path[MAX_PATH], command[2 * MAX_PATH];
    HANDLE done = NULL, read_pipe = NULL, write_pipe = NULL;
    ULONG table[16384], event, n, count, len;
    DWORD bytes, result, exit_code;
    NTSTATUS status;
    BOOL created;

    done = CreateEventW(&sa, TRUE, FALSE, NULL);
    ok(!!done, "CreateEvent failed\n");
    if (!done) goto cleanup;
    created = CreatePipe(&read_pipe, &write_pipe, &sa, 0);
    ok(created, "CreatePipe failed\n");
    if (!created) goto cleanup;
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);
    GetModuleFileNameA(NULL, path, sizeof(path));
    sprintf(command, "\"%s\" process_handle child %Ix %Ix", path, (ULONG_PTR)write_pipe, (ULONG_PTR)done);
    created = CreateProcessA(path, command, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    ok(created, "CreateProcess failed: %lu\n", GetLastError());
    if (!created) goto cleanup;
    CloseHandle(write_pipe);
    write_pipe = NULL;
    /* Bounded readiness: never block forever if the child failed to start. */
    for (result = 0; result < 200; ++result)
    {
        bytes = 0;
        if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &bytes, NULL) || bytes >= sizeof(event)) break;
        if (WaitForSingleObject(pi.hProcess, 50) != WAIT_TIMEOUT) break;
    }
    created = bytes >= sizeof(event) && ReadFile(read_pipe, &event, sizeof(event), &bytes, NULL);
    ok(created && bytes == sizeof(event), "Child did not report its event\n");
    if (created && bytes == sizeof(event))
    {
        test_access(pi.dwProcessId);
        n = check_snapshot(pi.hProcess, pi.dwProcessId, table, ARRAY_SIZE(table));
        ok(contains_handle(table, n, ULongToHandle(event)), "Missing child's own event %#lx\n", event);
        ok(contains_handle(table, n, done), "Missing child's inherited event\n");
        count = len = 0xdeadbeef;
        status = pNtQueryInformationProcess(pi.hProcess, ProcessHandleCount, &count, sizeof(count), &len);
        ok(!status && count == n, "Child count returned %#lx, %lu instead of %lu\n", status, count, n);
    }
    SetEvent(done);
    result = WaitForSingleObject(pi.hProcess, 5000);
    ok(result == WAIT_OBJECT_0, "Child did not exit: %#lx\n", result);
    if (result != WAIT_OBJECT_0)
    {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    exit_code = 0xdeadbeef;
    created = GetExitCodeProcess(pi.hProcess, &exit_code);
    ok(created, "GetExitCodeProcess failed: %lu\n", GetLastError());
    if (created) ok(!exit_code, "Child failed: %lu\n", exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
cleanup:
    if (write_pipe) CloseHandle(write_pipe);
    if (read_pipe) CloseHandle(read_pipe);
    if (done) CloseHandle(done);
}

START_TEST(process_handle)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (argc >= 5 && !strcmp(argv[2], "child"))
    {
        child_process(argv);
        return;
    }
    pNtQueryInformationProcess = (void *)GetProcAddress(ntdll, "NtQueryInformationProcess");
    pNtQuerySystemInformation = (void *)GetProcAddress(ntdll, "NtQuerySystemInformation");
    pGetProcessHandleCount = (void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcessHandleCount");
    ok(!!pNtQueryInformationProcess && !!pNtQuerySystemInformation, "Missing query exports\n");
    if (!pNtQueryInformationProcess || !pNtQuerySystemInformation) return;
    ok(!!pGetProcessHandleCount, "Missing GetProcessHandleCount\n");
    if (!pGetProcessHandleCount) return;
    test_own_handles();
    test_sizes_and_errors();
    test_access(GetCurrentProcessId());
    test_child();
}
