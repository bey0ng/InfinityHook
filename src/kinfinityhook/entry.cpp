/*
*	Module Name:
*		entry.cpp
*
*	Abstract:
*		Sample driver that implements infinity hook to detour
*		system calls.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "entry.h"
#include "infinityhook.h"

typedef NTSTATUS (NTAPI *NtTerminateProcess_t)(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);
static NtTerminateProcess_t OrigNtTerminateProcess = NULL;
NTSTATUS DetourNtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);

typedef PCHAR (*PsGetProcessImageFileName_t)(IN PEPROCESS);
static PsGetProcessImageFileName_t PsGetProcessImageFileName = NULL;

// 드라이버 메인
extern "C" 
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    kprintf("[+] infinityhook: Loaded.\n");

    // 드라이버 언로드 핸들러 등록
    DriverObject->DriverUnload = DriverUnload;

    // 후킹 시작(시스템콜이 발생하면, SyscallStub 함수로 제어권이 넘어감)
    NTSTATUS Status = IfhInitialize(SyscallStub);
    if (!NT_SUCCESS(Status)) kprintf("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);

    return Status;
}

// 드라이버 언로드할 때
void DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    // 후킹 종료
    IfhRelease();

    kprintf("\n[!] infinityhook: Unloading... BYE!\n");
}

void __fastcall SyscallStub(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction) {
    if (SystemCallIndex == 0x2c/*NtTerminateProcess 인덱스*/) {
        // 원본 NtTerminateProcess 주소를 백업
        if (OrigNtTerminateProcess == NULL)
            OrigNtTerminateProcess = (NtTerminateProcess_t)*SystemCallFunction;

        // NtTerminateProcess 함수 콜을 후킹 함수(DetourNtTerminateProcess)로 바꿔준다.
        *SystemCallFunction = DetourNtTerminateProcess; 
    }
}

// NtTerminateProcess 후킹 함수
NTSTATUS DetourNtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus) {

    NTSTATUS  rtStatus = STATUS_SUCCESS;
    PEPROCESS pEProcess = NULL;
    PCHAR pStrProcName = NULL;

    // 프로세스가 스스로 종료되는 것은 허용한다.
    if (NtCurrentProcess() == ProcessHandle) 
        return OrigNtTerminateProcess(ProcessHandle, ExitStatus);

    // 프로세스 핸들로부터 EPROCESS 구조체의 주소를 구한다.
    rtStatus = ObReferenceObjectByHandle(ProcessHandle, FILE_READ_DATA, NULL, KernelMode, (PVOID*)&pEProcess, NULL);
    if (!NT_SUCCESS(rtStatus) || pEProcess == NULL)
        return OrigNtTerminateProcess(ProcessHandle, ExitStatus);

    // EPROCESS 로부터 프로세스명을 구한다.
    if (PsGetProcessImageFileName == NULL) {
        UNICODE_STRING StringPsGetProcessImageFileName = RTL_CONSTANT_STRING(L"PsGetProcessImageFileName");
        PsGetProcessImageFileName = (PsGetProcessImageFileName_t)MmGetSystemRoutineAddress(&StringPsGetProcessImageFileName);
    }

    pStrProcName = (PCHAR)PsGetProcessImageFileName(pEProcess);
    bool block = pStrProcName != NULL && !strcmp(pStrProcName, "notepad.exe");

    // EPROCESS 구조체 참조 해제
    ObReferenceObject(pEProcess);

    if (block)	// 메모장(notepad.exe)이 종료되는 것을 막는다.
        return STATUS_SUCCESS;

    // 원본 NtTerminateProcess 호출
    return OrigNtTerminateProcess(ProcessHandle, ExitStatus);
}
