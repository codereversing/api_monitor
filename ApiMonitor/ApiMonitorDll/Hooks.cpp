#include "Hooks.h"

#include <assert.h>

#include <Windows.h>

#include "Common.h"

#define PAGE_SIZE 0x1000

static PVOID pHandler = NULL;
static DWORD_PTR dwHookId = 0;
static DWORD_PTR dwHookAddress = 0;
static DWORD_PTR dwHookNumParameters = 0;
static SOCKET sckOutgoing = INVALID_SOCKET;
static CRITICAL_SECTION critSec;
HANDLE hWaitEvent = NULL;

const bool InitializeHook(SOCKET socket)
{
    InitializeCriticalSection(&critSec);
    hWaitEvent = CreateEvent(NULL, FALSE, FALSE, L"Wait Event");
    pHandler = AddVectoredExceptionHandler(TRUE, ExceptionHandler);
    sckOutgoing = socket;

    return pHandler != NULL;
}

const bool ShutdownHook()
{
    DeleteCriticalSection(&critSec);
    CloseHandle(hWaitEvent);

    return RemoveVectoredExceptionHandler(pHandler) != 0;
}

const bool AddHook(const DWORD_PTR dwId, const char *pDllName, const char *pFunctionName, const DWORD_PTR dwNumParameters, DWORD_PTR *pOutAddress)
{
    HMODULE hModule = GetModuleHandleA(pDllName);

    dwHookId = dwId;
    dwHookAddress = (DWORD_PTR)GetProcAddress(hModule, pFunctionName);
    dwHookNumParameters = dwNumParameters;

    *pOutAddress = dwHookAddress;

    return AddPagePermissionFlag(dwHookAddress, PAGE_GUARD);
}

const bool RemoveHook(const DWORD_PTR dwId, const DWORD_PTR dwAddress)
{
    assert(dwId == dwHookId);

    dwHookId = 0;
    dwHookAddress = 0;
    dwHookNumParameters = 0;

    return RemovePagePermissionFlag(dwAddress, PAGE_GUARD);
}

static const bool AddPagePermissionFlag(const DWORD_PTR dwAddress, const DWORD_PTR dwProtectionFlag)
{
    MEMORY_BASIC_INFORMATION memBasicInfo = { 0 };
    DWORD dwOldProtect = 0;

    (void)VirtualQuery((LPCVOID)dwAddress, &memBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
    BOOL bRet = VirtualProtect((LPVOID)dwAddress, PAGE_SIZE, memBasicInfo.Protect | dwProtectionFlag, &dwOldProtect);

    return bRet == TRUE;
}

static const bool RemovePagePermissionFlag(const DWORD_PTR dwAddress, const DWORD_PTR dwProtectionFlag)
{
    MEMORY_BASIC_INFORMATION memBasicInfo = { 0 };
    DWORD dwOldProtect = 0;

    (void)VirtualQuery((LPCVOID)dwAddress, &memBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
    BOOL bRet = VirtualProtect((LPVOID)dwAddress, PAGE_SIZE, memBasicInfo.Protect & ~dwProtectionFlag, &dwOldProtect);

    return bRet == TRUE;
}

static LONG CALLBACK ExceptionHandler(EXCEPTION_POINTERS *pExceptionPointers)
{
    if(pExceptionPointers->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        CONTEXT *pContext = pExceptionPointers->ContextRecord;
        pContext->EFlags |= 0x100;

        if((DWORD_PTR)pExceptionPointers->ExceptionRecord->ExceptionAddress == dwHookAddress)
        {
            HookFunction(pContext);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if(pExceptionPointers->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
    {
        (void)AddPagePermissionFlag(dwHookAddress, PAGE_GUARD);

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void WINAPI HookFunction(CONTEXT *pContext)
{
    EnterCriticalSection(&critSec);

    ApiMonitor::ProtoBuf::MonitorMessage mCallMessage;
#ifdef _M_IX86
    for(DWORD_PTR i = 0; i < dwHookNumParameters; ++i)
    {
        DWORD_PTR dwParameter = *(DWORD_PTR *)(pContext->Esp + sizeof(DWORD_PTR) + (i * sizeof(DWORD_PTR)));
        mCallMessage.mutable_mcall()->add_uiparameter(dwParameter);
    }
#elif defined _M_AMD64
        mCallMessage.mutable_mcall()->add_uiparameter(pContext->Rcx);
        mCallMessage.mutable_mcall()->add_uiparameter(pContext->Rdx);
        mCallMessage.mutable_mcall()->add_uiparameter(pContext->R8);
        mCallMessage.mutable_mcall()->add_uiparameter(pContext->R9);
#else
#error "Unsupported platform"
#endif
    mCallMessage.mutable_mcall()->set_uihookid(dwHookId);

    SendOutgoingMessage(sckOutgoing, &mCallMessage);

    WaitForSingleObject(hWaitEvent, INFINITE);

    LeaveCriticalSection(&critSec);
}