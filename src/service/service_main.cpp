/**
 * РБПО — Windows Service
 *
 * Launches the tray application in every active terminal session (except 0),
 * monitors new user logons via SESSION_CHANGE notifications,
 * exposes an RPC interface over ALPC for remote stop,
 * and terminates all child processes on service shutdown.
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstdarg>

#include "rbpo_rpc_h.h"
#include "rbpo_rpc_constants.h"
#include "state.h"
#include "json_util.h"
#include "av_engine.h"

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static SERVICE_STATUS_HANDLE g_hServiceStatus = nullptr;
static SERVICE_STATUS        g_ServiceStatus  = {};
static std::vector<HANDLE>   g_childProcesses;
static CRITICAL_SECTION      g_cs;

// ---------------------------------------------------------------------------
// Diagnostic log — writes to rbpo-service.log next to the exe (used by state.cpp)
// ---------------------------------------------------------------------------
extern "C" void RBPOLog(const char* fmt, ...)
{
    static char logPath[MAX_PATH] = {};
    if (!logPath[0]) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string p(exePath);
        auto pos = p.find_last_of("\\/");
        if (pos != std::string::npos) p = p.substr(0, pos + 1);
        p += "rbpo-service.log";
        strncpy_s(logPath, p.c_str(), _TRUNCATE);
    }
    FILE* f = nullptr;
    fopen_s(&f, logPath, "a");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fprintf(f, "\n");
    fclose(f);
}

// ---------------------------------------------------------------------------
// RPC memory allocation (required by the RPC runtime)
// ---------------------------------------------------------------------------
void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER midl_user_free(void* p)         { free(p); }

// ---------------------------------------------------------------------------
// RPC interface implementation — Requirement 5
// Clients call this to stop the service.
// ---------------------------------------------------------------------------
void RBPOService_Stop(void)
{
    RBPOLog("RBPOService_Stop called by RPC client");
    RpcMgmtStopServerListening(nullptr);
}

// ---------------------------------------------------------------------------
// Helpers for RPC out-string allocation (must use midl_user_allocate)
// ---------------------------------------------------------------------------
static wchar_t* RpcDupW(const std::wstring& s)
{
    size_t bytes = (s.size() + 1) * sizeof(wchar_t);
    auto* p = static_cast<wchar_t*>(midl_user_allocate(bytes));
    if (!p) return nullptr;
    memcpy(p, s.c_str(), bytes);
    return p;
}

// ---------------------------------------------------------------------------
// RPC: GetCurrentUser — task 1.3
// ---------------------------------------------------------------------------
long RBPO_GetCurrentUser(long* authenticated, wchar_t** email, wchar_t** name)
{
    auto u = rbpo::GetUserInfo();
    *authenticated = u.authenticated ? 1 : 0;
    *email = RpcDupW(rbpo::Utf8ToWide(u.email));
    *name  = RpcDupW(rbpo::Utf8ToWide(u.name));
    return RBPO_OK;
}

// ---------------------------------------------------------------------------
// RPC: Login
// ---------------------------------------------------------------------------
long RBPO_Login(const wchar_t* email, const wchar_t* password, wchar_t** errorMessage)
{
    std::wstring err;
    int rc = rbpo::Login(email ? email : L"", password ? password : L"", err);
    *errorMessage = RpcDupW(err);
    if (rc == RBPO_OK)
        rbpo::AvLoadFromBackend(rbpo::StateGetAccessToken());
    return rc;
}

// ---------------------------------------------------------------------------
// RPC: Logout
// ---------------------------------------------------------------------------
long RBPO_Logout(void)
{
    return rbpo::Logout();
}

// ---------------------------------------------------------------------------
// RPC: GetLicenseStatus
// ---------------------------------------------------------------------------
long RBPO_GetLicenseStatus(long* hasLicense, wchar_t** expirationIso,
                           long* blocked, hyper* secondsLeft)
{
    auto l = rbpo::GetLicenseInfo();
    *hasLicense    = l.held ? 1 : 0;
    /* Tri-state: 0=none, 1=blocked by admin, 2=expired naturally. */
    if (l.blocked)       *blocked = 1;
    else if (l.expired)  *blocked = 2;
    else                 *blocked = 0;
    *secondsLeft   = static_cast<hyper>(l.secondsLeft);
    *expirationIso = RpcDupW(rbpo::Utf8ToWide(l.expirationIso));
    return RBPO_OK;
}

// ---------------------------------------------------------------------------
// RPC: ActivateProduct
// ---------------------------------------------------------------------------
long RBPO_ActivateProduct(const wchar_t* activationKey, wchar_t** errorMessage)
{
    std::wstring err;
    int rc = rbpo::Activate(activationKey ? activationKey : L"", err);
    *errorMessage = RpcDupW(err);
    return rc;
}

// ---------------------------------------------------------------------------
// RPC: AVPing — license-gated stub for AV functionality
// ---------------------------------------------------------------------------
long RBPO_AVPing(wchar_t** message)
{
    int gate = rbpo::LicenseGate();
    if (gate != RBPO_OK) {
        *message = RpcDupW(L"No active license");
        return RBPO_ERR_NO_LICENSE;
    }
    *message = RpcDupW(L"AV module ready");
    return RBPO_OK;
}

long RBPO_GetAvDbInfo(wchar_t** releaseDate, long* recordCount)
{
    rbpo::AvDbInfo info = rbpo::AvGetInfo();
    *releaseDate  = RpcDupW(info.date);
    *recordCount  = (long)info.count;
    return RBPO_OK;
}

long RBPO_ScanFile(const wchar_t* filePath, long* detected, wchar_t** threatName)
{
    int gate = rbpo::LicenseGate();
    if (gate != RBPO_OK) {
        *detected   = 0;
        *threatName = RpcDupW(L"No active license");
        return RBPO_ERR_NO_LICENSE;
    }
    std::wstring threat;
    bool found = rbpo::AvScanFile(filePath ? filePath : L"", threat);
    *detected   = found ? 1 : 0;
    *threatName = RpcDupW(threat);
    RBPOLog("ScanFile '%ls': detected=%d threat=%ls",
            filePath, *detected, threat.c_str());
    return RBPO_OK;
}

long RBPO_ScanDirectory(const wchar_t* dirPath, wchar_t** results)
{
    int gate = rbpo::LicenseGate();
    if (gate != RBPO_OK) {
        *results = RpcDupW(L"No active license");
        return RBPO_ERR_NO_LICENSE;
    }
    std::wstring res = rbpo::AvScanDirectory(dirPath ? dirPath : L"");
    if (res.empty()) res = L"No threats detected";
    *results = RpcDupW(res);
    RBPOLog("ScanDirectory '%ls': result len=%zu", dirPath, res.size());
    return RBPO_OK;
}

long RBPO_ScanAllDrives(wchar_t** results)
{
    int gate = rbpo::LicenseGate();
    if (gate != RBPO_OK) {
        *results = RpcDupW(L"No active license");
        return RBPO_ERR_NO_LICENSE;
    }
    std::wstring res = rbpo::AvScanAllDrives();
    *results = RpcDupW(res);
    RBPOLog("ScanAllDrives: result len=%zu", res.size());
    return RBPO_OK;
}

long RBPO_SetScanSchedule(const wchar_t* path, long intervalSeconds)
{
    int gate = rbpo::LicenseGate();
    if (gate != RBPO_OK) return RBPO_ERR_NO_LICENSE;
    rbpo::AvSetSchedule(path ? path : L"", intervalSeconds);
    return RBPO_OK;
}

long RBPO_ClearScanSchedule()
{
    rbpo::AvClearSchedule();
    return RBPO_OK;
}

long RBPO_GetScheduleResults(wchar_t** results, hyper* lastScanTimeUnix)
{
    int64_t t = 0;
    std::wstring res = rbpo::AvGetScheduleResults(t);
    *results         = RpcDupW(res);
    *lastScanTimeUnix = (hyper)t;
    return RBPO_OK;
}

long RBPO_AddMonitorDirectory(const wchar_t* path)
{
    int gate = rbpo::LicenseGate();
    if (gate != RBPO_OK) return RBPO_ERR_NO_LICENSE;
    rbpo::AvAddMonitorDirectory(path ? path : L"");
    return RBPO_OK;
}

long RBPO_RemoveMonitorDirectory(const wchar_t* path)
{
    rbpo::AvRemoveMonitorDirectory(path ? path : L"");
    return RBPO_OK;
}

long RBPO_GetMonitorResults(wchar_t** results)
{
    std::wstring res = rbpo::AvGetMonitorResults();
    *results = RpcDupW(res);
    return RBPO_OK;
}

// ---------------------------------------------------------------------------
// Get path to the GUI application (same directory as the service exe)
// ---------------------------------------------------------------------------
static std::wstring GetAppPath()
{
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring path(buf);
    auto pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        path = path.substr(0, pos + 1);
    path += RBPO_APP_EXE_NAME;
    return path;
}

// ---------------------------------------------------------------------------
// Launch the GUI app in a given terminal session — Requirements 1, 2
//   • Skips session 0
//   • Runs as the session owner
//   • Main window is hidden (--silent)
// ---------------------------------------------------------------------------
static void LaunchAppInSession(DWORD sessionId)
{
    if (sessionId == 0) return;

    HANDLE hToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &hToken)) {
        RBPOLog("  WTSQueryUserToken failed for session %u, error=%u", sessionId, GetLastError());
        return;
    }

    HANDLE hDupToken = nullptr;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr,
                          SecurityIdentification, TokenPrimary, &hDupToken)) {
        RBPOLog("  DuplicateTokenEx failed, error=%u", GetLastError());
        CloseHandle(hToken);
        return;
    }
    CloseHandle(hToken);

    LPVOID pEnv = nullptr;
    CreateEnvironmentBlock(&pEnv, hDupToken, FALSE);

    std::wstring appPath = GetAppPath();
    std::wstring cmdLine = L"\"" + appPath + L"\" --silent";

    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop   = const_cast<LPWSTR>(L"winsta0\\default");
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};

    // writable copy of the command line (CreateProcessAsUser requirement)
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    if (CreateProcessAsUserW(hDupToken, appPath.c_str(), cmdBuf.data(),
                             nullptr, nullptr, FALSE,
                             CREATE_UNICODE_ENVIRONMENT,
                             pEnv, nullptr, &si, &pi)) {
        RBPOLog("  Launched PID=%u in session %u", pi.dwProcessId, sessionId);
        EnterCriticalSection(&g_cs);
        g_childProcesses.push_back(pi.hProcess);
        LeaveCriticalSection(&g_cs);
        CloseHandle(pi.hThread);
    } else {
        RBPOLog("  CreateProcessAsUserW failed, error=%u", GetLastError());
    }

    if (pEnv) DestroyEnvironmentBlock(pEnv);
    CloseHandle(hDupToken);
}

// ---------------------------------------------------------------------------
// Terminate all launched GUI applications — Requirement 6
// ---------------------------------------------------------------------------
static void TerminateAllChildren()
{
    EnterCriticalSection(&g_cs);
    for (HANDLE h : g_childProcesses) {
        TerminateProcess(h, 0);
        CloseHandle(h);
    }
    g_childProcesses.clear();
    LeaveCriticalSection(&g_cs);
}

// ---------------------------------------------------------------------------
// Service control handler
//   • Requirement 3: ignores SERVICE_CONTROL_STOP and SERVICE_CONTROL_SHUTDOWN
//   • Requirement 2: launches app on WTS_SESSION_LOGON
// ---------------------------------------------------------------------------
static DWORD WINAPI ServiceCtrlHandlerEx(DWORD dwControl, DWORD dwEventType,
                                          LPVOID lpEventData, LPVOID)
{
    switch (dwControl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        // Requirement 3: disable Stop and Shutdown handling
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE:
        // Requirement 2: launch app when a new user logs on
        if (dwEventType == WTS_SESSION_LOGON) {
            auto* pNotify = reinterpret_cast<WTSSESSION_NOTIFICATION*>(lpEventData);
            LaunchAppInSession(pNotify->dwSessionId);
        }
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

// ---------------------------------------------------------------------------
// ServiceMain — entry point called by the SCM
// ---------------------------------------------------------------------------
static void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    InitializeCriticalSection(&g_cs);

    RBPOLog("=== ServiceMain started (PID=%u) ===", GetCurrentProcessId());

    g_hServiceStatus = RegisterServiceCtrlHandlerExW(
        RBPO_SERVICE_NAME, ServiceCtrlHandlerEx, nullptr);
    if (!g_hServiceStatus) { RBPOLog("RegisterServiceCtrlHandlerExW failed"); return; }

    // Report SERVICE_START_PENDING
    g_ServiceStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState     = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;
    // NOTE: SERVICE_ACCEPT_STOP and SERVICE_ACCEPT_SHUTDOWN are deliberately omitted
    SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

    // --- Requirement 4: start RPC server with ALPC transport -----------------
    RPC_STATUS rpcStatus;
    rpcStatus = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(RBPO_RPC_ENDPOINT)),
        nullptr);

    RBPOLog("RpcServerUseProtseqEpW returned %d", rpcStatus);
    if (rpcStatus != RPC_S_OK) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = rpcStatus;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);
        DeleteCriticalSection(&g_cs);
        return;
    }

    // --- Requirement 5: register the RPC interface ---------------------------
    rpcStatus = RpcServerRegisterIf(RBPOServiceRpc_v1_0_s_ifspec, nullptr, nullptr);
    RBPOLog("RpcServerRegisterIf returned %d", rpcStatus);
    if (rpcStatus != RPC_S_OK) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = rpcStatus;
        SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);
        DeleteCriticalSection(&g_cs);
        return;
    }

    /* RUNNING до запуска клиентов: rbpo-app проверяет SCM и ждёт SERVICE_RUNNING. */
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);
    RBPOLog("Service RUNNING (before session launches)");

    rbpo::AvLoad();
    rbpo::AvDbStartUpdate(3600);

    // --- Requirement 1: launch app in all existing active sessions -----------
    WTS_SESSION_INFOW* pSessions = nullptr;
    DWORD sessionCount = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                               &pSessions, &sessionCount)) {
        RBPOLog("Enumerated %u sessions", sessionCount);
        for (DWORD i = 0; i < sessionCount; i++) {
            RBPOLog("  Session %u: id=%u state=%d",
                i, pSessions[i].SessionId, pSessions[i].State);
            if (pSessions[i].SessionId != 0 && pSessions[i].State == WTSActive)
                LaunchAppInSession(pSessions[i].SessionId);
        }
        WTSFreeMemory(pSessions);
    } else {
        RBPOLog("WTSEnumerateSessionsW failed, error=%u", GetLastError());
    }

    RBPOLog("Entering RpcServerListen...");

    // --- Task 1.3: start auth/license background workers ----------------------
    rbpo::StateInit();

    // --- Requirement 4: blocks until RpcMgmtStopServerListening is called ----
    rpcStatus = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
    RBPOLog("RpcServerListen returned %d", rpcStatus);

    rbpo::AvShutdown();

    // --- Task 1.3: stop background workers -----------------------------------
    rbpo::StateShutdown();

    // --- Requirement 6: terminate all child processes on stop ----------------
    TerminateAllChildren();

    RpcServerUnregisterIf(RBPOServiceRpc_v1_0_s_ifspec, nullptr, FALSE);

    // Report SERVICE_STOPPED
    RBPOLog("Service STOPPED");
    g_ServiceStatus.dwCurrentState     = SERVICE_STOPPED;
    g_ServiceStatus.dwControlsAccepted = 0;
    SetServiceStatus(g_hServiceStatus, &g_ServiceStatus);

    DeleteCriticalSection(&g_cs);
}

// ---------------------------------------------------------------------------
// main — dispatches the service to the SCM
// ---------------------------------------------------------------------------
int wmain()
{
    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { const_cast<LPWSTR>(RBPO_SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(serviceTable);
    return 0;
}
