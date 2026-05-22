/**
 * РБПО — Qt Tray Application
 * Qt6 Widgets UI; Win32 RPC + SCM for service communication.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

// Win32 (RPC + SCM only)
#include <windows.h>
#include <tlhelp32.h>
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <string>

// Qt
#include <QApplication>
#include <QMainWindow>
#include <QStackedWidget>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QGroupBox>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QTimer>
#include <QMessageBox>
#include <QFileDialog>
#include <QEvent>
#include <QIcon>

// RPC
#include "rbpo_rpc_h.h"
#include "rbpo_rpc_constants.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static const wchar_t APP_MUTEX_NAME[] = L"Local\\RBPO_TrayApp_SingleInstance";

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static HANDLE           g_hMutex   = nullptr;
static bool             g_rpcBound = false;

static QMainWindow*     g_mainWnd  = nullptr;
static QStackedWidget*  g_stack    = nullptr;
static QSystemTrayIcon* g_tray     = nullptr;

// Login page
static QLineEdit* g_loginEmail  = nullptr;
static QLineEdit* g_loginPass   = nullptr;
static QLabel*    g_loginStatus = nullptr;

// Activate page
static QLabel*      g_actUserLbl = nullptr;
static QLabel*      g_actLicLbl  = nullptr;
static QLineEdit*   g_actKey     = nullptr;
static QPushButton* g_actBtn     = nullptr;
static QLabel*      g_actStatus  = nullptr;

// Licensed page
static QLabel*    g_licUserLbl    = nullptr;
static QLabel*    g_licLicLbl     = nullptr;
static QLabel*    g_avDbLbl       = nullptr;
static QLineEdit* g_schedPathEdit = nullptr;
static QLineEdit* g_schedIntvEdit = nullptr;
static QLineEdit* g_monPathEdit   = nullptr;

// ---------------------------------------------------------------------------
// RPC memory
// ---------------------------------------------------------------------------
void* __RPC_USER midl_user_allocate(size_t size) { return malloc(size); }
void  __RPC_USER midl_user_free(void* p)         { free(p); }

// ---------------------------------------------------------------------------
// Diagnostic log
// ---------------------------------------------------------------------------
static void Log(const char* fmt, ...)
{
    static char logPath[MAX_PATH] = {};
    if (!logPath[0]) {
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string p(exePath);
        auto pos = p.find_last_of("\\/");
        if (pos != std::string::npos) p = p.substr(0, pos + 1);
        p += "rbpo-app.log";
        strncpy_s(logPath, p.c_str(), _TRUNCATE);
    }
    FILE* f = nullptr;
    fopen_s(&f, logPath, "a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args; va_start(args, fmt); vfprintf(f, fmt, args); va_end(args);
    fprintf(f, "\n"); fclose(f);
}

// ---------------------------------------------------------------------------
// Service helpers
// ---------------------------------------------------------------------------
static bool IsServiceRunning()
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = OpenServiceW(hSCM, RBPO_SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); return false; }
    SERVICE_STATUS status = {};
    QueryServiceStatus(hSvc, &status);
    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    return status.dwCurrentState == SERVICE_RUNNING;
}

static bool StartServiceAndWait()
{
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hSvc = OpenServiceW(hSCM, RBPO_SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); return false; }
    if (!StartServiceW(hSvc, 0, nullptr)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM); return false;
        }
    }
    SERVICE_STATUS status = {};
    for (int i = 0; i < 60; i++) {
        QueryServiceStatus(hSvc, &status);
        if (status.dwCurrentState == SERVICE_RUNNING) break;
        Sleep(500);
    }
    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
    return status.dwCurrentState == SERVICE_RUNNING;
}

static bool IsParentService()
{
    DWORD pid = GetCurrentProcessId(), ppid = 0;
    wchar_t parentExe[MAX_PATH] = {};
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do { if (pe.th32ProcessID == pid) { ppid = pe.th32ParentProcessID; break; } }
        while (Process32NextW(hSnap, &pe));
    }
    if (ppid) {
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do { if (pe.th32ProcessID == ppid) { wcscpy_s(parentExe, pe.szExeFile); break; } }
            while (Process32NextW(hSnap, &pe));
        }
    }
    CloseHandle(hSnap);
    return parentExe[0] && _wcsicmp(parentExe, RBPO_SERVICE_EXE_NAME) == 0;
}

// ---------------------------------------------------------------------------
// RPC binding
// ---------------------------------------------------------------------------
static bool BindRpc()
{
    if (g_rpcBound) return true;
    RPC_WSTR sb = nullptr;
    RPC_STATUS s = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(RBPO_RPC_ENDPOINT)),
        nullptr, &sb);
    if (s != RPC_S_OK) return false;
    s = RpcBindingFromStringBindingW(sb, &hRBPOServiceBinding);
    RpcStringFreeW(&sb);
    if (s != RPC_S_OK) return false;
    g_rpcBound = true;
    return true;
}

static void UnbindRpc()
{
    if (!g_rpcBound) return;
    RpcBindingFree(&hRBPOServiceBinding);
    g_rpcBound = false;
}

static void StopServiceViaRpc()
{
    if (!BindRpc()) return;
    RpcTryExcept { RBPOService_Stop(); }
    RpcExcept(1) {} RpcEndExcept
    UnbindRpc();
}

// ---------------------------------------------------------------------------
// RPC operations
// ---------------------------------------------------------------------------
static int RpcGetCurrentUser(bool& authenticated, std::wstring& email, std::wstring& name)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long auth = 0; long rc = RBPO_ERR_GENERIC;
    wchar_t* e = nullptr; wchar_t* n = nullptr;
    RpcTryExcept { rc = RBPO_GetCurrentUser(&auth, &e, &n); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    authenticated = (auth != 0);
    email = e ? e : L""; name = n ? n : L"";
    if (e) midl_user_free(e); if (n) midl_user_free(n);
    return (int)rc;
}

static int RpcLogin(const std::wstring& email, const std::wstring& password, std::wstring& errMsg)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; wchar_t* err = nullptr;
    RpcTryExcept { rc = RBPO_Login(email.c_str(), password.c_str(), &err); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    errMsg = err ? err : L""; if (err) midl_user_free(err);
    return (int)rc;
}

static int RpcLogout()
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC;
    RpcTryExcept { rc = RBPO_Logout(); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    return (int)rc;
}

static int RpcLicenseStatus(bool& has, std::wstring& expIso,
                            bool& blocked, bool& expired, long long& secLeft)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long h = 0, b = 0; __int64 sl = 0; wchar_t* e = nullptr; long rc = RBPO_ERR_GENERIC;
    RpcTryExcept { rc = RBPO_GetLicenseStatus(&h, &e, &b, &sl); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    has = (h != 0); blocked = (b == 1); expired = (b == 2); secLeft = (long long)sl;
    expIso = e ? e : L""; if (e) midl_user_free(e);
    return (int)rc;
}

static int RpcActivate(const std::wstring& key, std::wstring& errMsg)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; wchar_t* err = nullptr;
    RpcTryExcept { rc = RBPO_ActivateProduct(key.c_str(), &err); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    errMsg = err ? err : L""; if (err) midl_user_free(err);
    return (int)rc;
}

static int RpcAVPing(std::wstring& message)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; wchar_t* msg = nullptr;
    RpcTryExcept { rc = RBPO_AVPing(&msg); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    message = msg ? msg : L"(no message)"; if (msg) midl_user_free(msg);
    return (int)rc;
}

static int RpcGetAvDbInfo(std::wstring& date, long& count)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; wchar_t* d = nullptr; long cnt = 0;
    RpcTryExcept { rc = RBPO_GetAvDbInfo(&d, &cnt); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    date = d ? d : L""; count = cnt; if (d) midl_user_free(d);
    return (int)rc;
}

static int RpcScanFile(const std::wstring& path, bool& detected, std::wstring& threat)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; long det = 0; wchar_t* t = nullptr;
    RpcTryExcept { rc = RBPO_ScanFile(path.c_str(), &det, &t); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    detected = (det != 0); threat = t ? t : L""; if (t) midl_user_free(t);
    return (int)rc;
}

static int RpcScanDirectory(const std::wstring& path, std::wstring& results)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; wchar_t* r = nullptr;
    RpcTryExcept { rc = RBPO_ScanDirectory(path.c_str(), &r); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    results = r ? r : L""; if (r) midl_user_free(r);
    return (int)rc;
}

static int RpcScanAllDrives(std::wstring& results)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; wchar_t* r = nullptr;
    RpcTryExcept { rc = RBPO_ScanAllDrives(&r); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    results = r ? r : L""; if (r) midl_user_free(r);
    return (int)rc;
}

static int RpcSetScanSchedule(const std::wstring& path, long interval)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC;
    RpcTryExcept { rc = RBPO_SetScanSchedule(path.c_str(), interval); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    return (int)rc;
}

static int RpcClearScanSchedule()
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC;
    RpcTryExcept { rc = RBPO_ClearScanSchedule(); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    return (int)rc;
}

static int RpcGetScheduleResults(std::wstring& results, int64_t& lastTime)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; wchar_t* r = nullptr; __int64 t = 0;
    RpcTryExcept { rc = RBPO_GetScheduleResults(&r, &t); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    results = r ? r : L""; lastTime = (int64_t)t; if (r) midl_user_free(r);
    return (int)rc;
}

static int RpcAddMonitorDirectory(const std::wstring& path)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC;
    RpcTryExcept { rc = RBPO_AddMonitorDirectory(path.c_str()); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    return (int)rc;
}

static int RpcRemoveMonitorDirectory(const std::wstring& path)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC;
    RpcTryExcept { rc = RBPO_RemoveMonitorDirectory(path.c_str()); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    return (int)rc;
}

static int RpcGetMonitorResults(std::wstring& results)
{
    if (!BindRpc()) return RBPO_ERR_NETWORK;
    long rc = RBPO_ERR_GENERIC; wchar_t* r = nullptr;
    RpcTryExcept { rc = RBPO_GetMonitorResults(&r); }
    RpcExcept(1) { return RBPO_ERR_NETWORK; } RpcEndExcept
    results = r ? r : L""; if (r) midl_user_free(r);
    return (int)rc;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static inline QString W(const std::wstring& s) { return QString::fromStdWString(s); }

// Close event → hide window instead of quitting
class HideOnClose : public QObject {
public:
    bool eventFilter(QObject* obj, QEvent* ev) override {
        if (ev->type() == QEvent::Close) {
            static_cast<QWidget*>(obj)->hide();
            return true;
        }
        return QObject::eventFilter(obj, ev);
    }
};

// Forward declarations
static void RefreshUI();
static void DoLogin();
static void DoLogout();
static void DoActivate();
static void DoScanFile();
static void DoScanDirectory();
static void DoScanAllDrives();
static void DoSetSchedule();
static void DoClearSchedule();
static void DoGetScheduleResults();
static void DoAddMonitor();
static void DoRemoveMonitor();
static void DoGetMonitorResults();

// ---------------------------------------------------------------------------
// UI: page builders
// ---------------------------------------------------------------------------
static QWidget* BuildLoginPage()
{
    QWidget* page = new QWidget();
    QVBoxLayout* root = new QVBoxLayout(page);
    root->setContentsMargins(48, 40, 48, 40);
    root->setSpacing(14);

    QLabel* title = new QLabel("Вход в учётную запись");
    QFont tf = title->font();
    tf.setPointSize(15); tf.setBold(true);
    title->setFont(tf);
    root->addWidget(title);
    root->addSpacing(8);

    QFormLayout* form = new QFormLayout();
    form->setSpacing(10);
    form->setLabelAlignment(Qt::AlignRight);
    g_loginEmail = new QLineEdit();
    g_loginEmail->setPlaceholderText("user@example.com");
    g_loginEmail->setFixedHeight(30);
    g_loginPass = new QLineEdit();
    g_loginPass->setEchoMode(QLineEdit::Password);
    g_loginPass->setFixedHeight(30);
    form->addRow("Email:", g_loginEmail);
    form->addRow("Пароль:", g_loginPass);
    root->addLayout(form);

    QPushButton* btn = new QPushButton("Войти");
    btn->setFixedHeight(36);
    btn->setDefault(true);
    QObject::connect(btn, &QPushButton::clicked, DoLogin);
    QObject::connect(g_loginPass,  &QLineEdit::returnPressed, DoLogin);
    QObject::connect(g_loginEmail, &QLineEdit::returnPressed, []{ g_loginPass->setFocus(); });
    root->addWidget(btn);

    g_loginStatus = new QLabel();
    g_loginStatus->setWordWrap(true);
    g_loginStatus->setStyleSheet("color:#c0392b; font-size:12px;");
    root->addWidget(g_loginStatus);
    root->addStretch();
    return page;
}

static QWidget* BuildActivatePage()
{
    QWidget* page = new QWidget();
    QVBoxLayout* root = new QVBoxLayout(page);
    root->setContentsMargins(32, 24, 32, 24);
    root->setSpacing(10);

    g_actUserLbl = new QLabel();
    QFont uf = g_actUserLbl->font(); uf.setPointSize(11); g_actUserLbl->setFont(uf);
    g_actLicLbl = new QLabel();
    g_actLicLbl->setStyleSheet("color:#e67e22;");
    root->addWidget(g_actUserLbl);
    root->addWidget(g_actLicLbl);
    root->addSpacing(12);

    root->addWidget(new QLabel("Введите код активации:"));
    QHBoxLayout* row = new QHBoxLayout();
    g_actKey = new QLineEdit();
    g_actKey->setPlaceholderText("XXXX-XXXX-XXXX-XXXX");
    g_actKey->setFixedHeight(30);
    g_actBtn = new QPushButton("Активировать");
    g_actBtn->setFixedWidth(140);
    g_actBtn->setFixedHeight(30);
    row->addWidget(g_actKey);
    row->addWidget(g_actBtn);
    root->addLayout(row);

    QObject::connect(g_actBtn, &QPushButton::clicked, DoActivate);
    QObject::connect(g_actKey, &QLineEdit::returnPressed, DoActivate);

    g_actStatus = new QLabel();
    g_actStatus->setWordWrap(true);
    g_actStatus->setStyleSheet("color:#c0392b;");
    root->addWidget(g_actStatus);
    root->addStretch();

    QPushButton* logoutBtn = new QPushButton("Выйти из аккаунта");
    logoutBtn->setFixedHeight(32);
    QObject::connect(logoutBtn, &QPushButton::clicked, DoLogout);
    root->addWidget(logoutBtn);
    return page;
}

static QWidget* BuildLicensedPage()
{
    QWidget* page = new QWidget();
    QVBoxLayout* root = new QVBoxLayout(page);
    root->setContentsMargins(20, 16, 20, 16);
    root->setSpacing(8);

    g_licUserLbl = new QLabel();
    QFont uf = g_licUserLbl->font(); uf.setPointSize(11); g_licUserLbl->setFont(uf);
    g_licLicLbl = new QLabel();
    g_licLicLbl->setStyleSheet("color:#27ae60; font-weight:bold;");
    g_avDbLbl = new QLabel("Антивирусная база: загрузка...");
    g_avDbLbl->setStyleSheet("color:#555; font-size:11px;");
    root->addWidget(g_licUserLbl);
    root->addWidget(g_licLicLbl);
    root->addWidget(g_avDbLbl);

    // Scan group
    QGroupBox* scanGroup = new QGroupBox("Сканирование");
    QHBoxLayout* scanRow = new QHBoxLayout(scanGroup);
    QPushButton* scanFileBtn = new QPushButton("Файл...");
    QPushButton* scanDirBtn  = new QPushButton("Папка...");
    QPushButton* scanAllBtn  = new QPushButton("Все диски");
    QPushButton* avPingBtn   = new QPushButton("AV Ping");
    for (auto* b : {scanFileBtn, scanDirBtn, scanAllBtn, avPingBtn})
        b->setFixedHeight(30);
    scanRow->addWidget(scanFileBtn);
    scanRow->addWidget(scanDirBtn);
    scanRow->addWidget(scanAllBtn);
    scanRow->addWidget(avPingBtn);
    root->addWidget(scanGroup);

    QObject::connect(scanFileBtn, &QPushButton::clicked, DoScanFile);
    QObject::connect(scanDirBtn,  &QPushButton::clicked, DoScanDirectory);
    QObject::connect(scanAllBtn,  &QPushButton::clicked, DoScanAllDrives);
    QObject::connect(avPingBtn,   &QPushButton::clicked, []{
        std::wstring m; int rc = RpcAVPing(m);
        QMessageBox::information(g_mainWnd, "AV",
            rc == RBPO_OK ? ("AV: " + W(m)) : ("AV blocked: " + W(m)));
    });

    // Schedule group
    QGroupBox* schedGroup = new QGroupBox("Расписание сканирования");
    QVBoxLayout* schedV = new QVBoxLayout(schedGroup);
    QHBoxLayout* schedRow1 = new QHBoxLayout();
    g_schedPathEdit = new QLineEdit();
    g_schedPathEdit->setPlaceholderText("Путь к директории");
    g_schedPathEdit->setFixedHeight(28);
    g_schedIntvEdit = new QLineEdit("3600");
    g_schedIntvEdit->setFixedWidth(65);
    g_schedIntvEdit->setFixedHeight(28);
    schedRow1->addWidget(g_schedPathEdit);
    schedRow1->addWidget(new QLabel("сек:"));
    schedRow1->addWidget(g_schedIntvEdit);
    schedV->addLayout(schedRow1);
    QHBoxLayout* schedRow2 = new QHBoxLayout();
    QPushButton* schedSetBtn     = new QPushButton("Установить");
    QPushButton* schedClearBtn   = new QPushButton("Сбросить");
    QPushButton* schedResultsBtn = new QPushButton("Результаты");
    for (auto* b : {schedSetBtn, schedClearBtn, schedResultsBtn}) b->setFixedHeight(28);
    schedRow2->addWidget(schedSetBtn);
    schedRow2->addWidget(schedClearBtn);
    schedRow2->addWidget(schedResultsBtn);
    schedRow2->addStretch();
    schedV->addLayout(schedRow2);
    root->addWidget(schedGroup);

    QObject::connect(schedSetBtn,     &QPushButton::clicked, DoSetSchedule);
    QObject::connect(schedClearBtn,   &QPushButton::clicked, DoClearSchedule);
    QObject::connect(schedResultsBtn, &QPushButton::clicked, DoGetScheduleResults);

    // Monitor group
    QGroupBox* monGroup = new QGroupBox("Мониторинг директорий");
    QVBoxLayout* monV = new QVBoxLayout(monGroup);
    g_monPathEdit = new QLineEdit();
    g_monPathEdit->setPlaceholderText("Путь к директории");
    g_monPathEdit->setFixedHeight(28);
    monV->addWidget(g_monPathEdit);
    QHBoxLayout* monRow = new QHBoxLayout();
    QPushButton* monAddBtn     = new QPushButton("Добавить");
    QPushButton* monRemoveBtn  = new QPushButton("Удалить");
    QPushButton* monResultsBtn = new QPushButton("Результаты");
    for (auto* b : {monAddBtn, monRemoveBtn, monResultsBtn}) b->setFixedHeight(28);
    monRow->addWidget(monAddBtn);
    monRow->addWidget(monRemoveBtn);
    monRow->addWidget(monResultsBtn);
    monRow->addStretch();
    monV->addLayout(monRow);
    root->addWidget(monGroup);

    QObject::connect(monAddBtn,     &QPushButton::clicked, DoAddMonitor);
    QObject::connect(monRemoveBtn,  &QPushButton::clicked, DoRemoveMonitor);
    QObject::connect(monResultsBtn, &QPushButton::clicked, DoGetMonitorResults);

    root->addStretch();
    QPushButton* logoutBtn = new QPushButton("Выйти из аккаунта");
    logoutBtn->setFixedHeight(32);
    QObject::connect(logoutBtn, &QPushButton::clicked, DoLogout);
    root->addWidget(logoutBtn);
    return page;
}

// ---------------------------------------------------------------------------
// State refresh — switches the active page
// ---------------------------------------------------------------------------
static void RefreshUI()
{
    bool authed = false; std::wstring email, name;
    int rc = RpcGetCurrentUser(authed, email, name);
    if (rc != RBPO_OK) {
        g_stack->setCurrentIndex(0);
        if (g_loginStatus) g_loginStatus->setText("Нет связи со службой");
        return;
    }
    if (!authed) {
        g_stack->setCurrentIndex(0);
        return;
    }

    bool has = false, blocked = false, expired = false;
    std::wstring expIso; long long secLeft = 0;
    if (RpcLicenseStatus(has, expIso, blocked, expired, secLeft) != RBPO_OK) has = false;

    std::wstring userText = L"Пользователь: ";
    userText += name.empty() ? email : (name + L" (" + email + L")");

    if (has && !blocked && secLeft > 0) {
        std::wstring licText = L"Лицензия активна до: " + expIso;
        if (g_licUserLbl) g_licUserLbl->setText(W(userText));
        if (g_licLicLbl)  g_licLicLbl->setText(W(licText));
        g_stack->setCurrentIndex(2);
        std::wstring dbDate; long dbCount = 0;
        if (RpcGetAvDbInfo(dbDate, dbCount) == RBPO_OK && g_avDbLbl)
            g_avDbLbl->setText(W(L"Антивирусная база: " + dbDate +
                                  L"  |  Записей: " + std::to_wstring(dbCount)));
    } else {
        std::wstring licText;
        if (blocked && !expIso.empty())      licText = L"Лицензия заблокирована (" + expIso + L")";
        else if (blocked)                    licText = L"Лицензия заблокирована";
        else if (expired && !expIso.empty()) licText = L"Лицензия истекла (" + expIso + L")";
        else if (expired)                    licText = L"Лицензия истекла";
        else                                 licText = L"Лицензия отсутствует";
        if (g_actUserLbl) g_actUserLbl->setText(W(userText));
        if (g_actLicLbl)  g_actLicLbl->setText(W(licText));
        g_stack->setCurrentIndex(1);
    }
}

// ---------------------------------------------------------------------------
// Action handlers
// ---------------------------------------------------------------------------
static void DoLogin()
{
    if (!g_loginEmail || !g_loginPass) return;
    std::wstring email = g_loginEmail->text().toStdWString();
    std::wstring pass  = g_loginPass->text().toStdWString();
    if (email.empty() || pass.empty()) {
        g_loginStatus->setText("Введите email и пароль");
        return;
    }
    g_loginStatus->setText("Выполняется вход...");
    std::wstring err;
    int rc = RpcLogin(email, pass, err);
    g_loginPass->clear();
    if (rc != RBPO_OK) {
        g_loginStatus->setText("Ошибка входа: " + W(err.empty() ? L"unknown" : err));
        g_loginPass->setFocus();
        return;
    }
    g_loginStatus->clear();
    RefreshUI();
}

static void DoLogout()
{
    RpcLogout();
    g_stack->setCurrentIndex(0);
}

static void DoActivate()
{
    if (!g_actKey || !g_actBtn) return;
    std::wstring key = g_actKey->text().toStdWString();
    if (key.empty()) { g_actStatus->setText("Введите код активации"); return; }
    g_actStatus->setText("Активация...");
    g_actBtn->setEnabled(false);
    std::wstring err;
    int rc = RpcActivate(key, err);
    g_actBtn->setEnabled(true);
    if (rc != RBPO_OK) {
        g_actStatus->setText("Ошибка активации: " + W(err.empty() ? L"unknown" : err));
        g_actKey->clear(); g_actKey->setFocus();
        return;
    }
    g_actKey->clear(); g_actStatus->clear();
    RefreshUI();
}

static void DoScanFile()
{
    QString path = QFileDialog::getOpenFileName(
        g_mainWnd, "Выберите файл для сканирования", "", "Все файлы (*.*)");
    if (path.isEmpty()) return;
    bool detected = false; std::wstring threat;
    int rc = RpcScanFile(path.toStdWString(), detected, threat);
    if (rc == RBPO_ERR_NO_LICENSE) {
        QMessageBox::warning(g_mainWnd, "Сканирование", "Требуется активная лицензия"); return;
    }
    if (rc != RBPO_OK) {
        QMessageBox::critical(g_mainWnd, "Сканирование", "Ошибка связи со службой"); return;
    }
    if (detected)
        QMessageBox::warning(g_mainWnd, "Обнаружена угроза",
            "Файл: " + path + "\nУгроза: " + W(threat));
    else
        QMessageBox::information(g_mainWnd, "Файл чист", "Угрозы не обнаружены:\n" + path);
}

static void DoScanDirectory()
{
    QString dir = QFileDialog::getExistingDirectory(
        g_mainWnd, "Выберите папку для сканирования");
    if (dir.isEmpty()) return;
    std::wstring results;
    int rc = RpcScanDirectory(dir.toStdWString(), results);
    if (rc == RBPO_ERR_NO_LICENSE) {
        QMessageBox::warning(g_mainWnd, "Сканирование", "Требуется активная лицензия"); return;
    }
    if (rc != RBPO_OK) {
        QMessageBox::critical(g_mainWnd, "Сканирование", "Ошибка связи со службой"); return;
    }
    QString msg = "Папка: " + dir + "\n\n" + W(results);
    if (results == L"No threats detected")
        QMessageBox::information(g_mainWnd, "Угрозы не обнаружены", msg);
    else
        QMessageBox::warning(g_mainWnd, "Обнаружены угрозы", msg);
}

static void DoScanAllDrives()
{
    std::wstring results;
    int rc = RpcScanAllDrives(results);
    if (rc == RBPO_ERR_NO_LICENSE) {
        QMessageBox::warning(g_mainWnd, "Сканирование дисков", "Требуется активная лицензия"); return;
    }
    if (rc != RBPO_OK) {
        QMessageBox::critical(g_mainWnd, "Сканирование дисков", "Ошибка связи со службой"); return;
    }
    if (results == L"No threats detected")
        QMessageBox::information(g_mainWnd, "Диски чисты", W(results));
    else
        QMessageBox::warning(g_mainWnd, "Обнаружены угрозы", W(results));
}

static void DoSetSchedule()
{
    if (!g_schedPathEdit || !g_schedIntvEdit) return;
    std::wstring path    = g_schedPathEdit->text().toStdWString();
    std::wstring intvStr = g_schedIntvEdit->text().toStdWString();
    if (path.empty()) {
        QMessageBox::warning(g_mainWnd, "Расписание", "Введите путь для сканирования"); return;
    }
    long interval = intvStr.empty() ? 3600L : (long)_wtoi(intvStr.c_str());
    int rc = RpcSetScanSchedule(path, interval);
    if (rc == RBPO_ERR_NO_LICENSE) {
        QMessageBox::warning(g_mainWnd, "Расписание", "Требуется активная лицензия"); return;
    }
    QMessageBox::information(g_mainWnd, "Расписание",
        rc == RBPO_OK
            ? ("Расписание установлено.\nПуть: " + W(path) +
               "\nИнтервал: " + QString::number(interval) + " сек")
            : "Ошибка связи со службой");
}

static void DoClearSchedule()
{
    int rc = RpcClearScanSchedule();
    QMessageBox::information(g_mainWnd, "Расписание",
        rc == RBPO_OK ? "Расписание сброшено" : "Ошибка связи со службой");
}

static void DoGetScheduleResults()
{
    std::wstring results; int64_t lastTime = 0;
    int rc = RpcGetScheduleResults(results, lastTime);
    if (rc != RBPO_OK) {
        QMessageBox::critical(g_mainWnd, "Расписание", "Ошибка связи со службой"); return;
    }
    QString msg;
    if (lastTime > 0) {
        time_t t = (time_t)lastTime;
        char tbuf[64] = {}; struct tm tms = {};
        localtime_s(&tms, &t);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tms);
        msg = QString("Последнее сканирование: %1\n\n").arg(tbuf);
    } else {
        msg = "Сканирование ещё не выполнялось.\n\n";
    }
    msg += W(results);
    bool clean = (results == L"No scan results yet" || results == L"No threats detected");
    if (clean) QMessageBox::information(g_mainWnd, "Угрозы не обнаружены", msg);
    else       QMessageBox::warning(g_mainWnd, "Обнаружены угрозы", msg);
}

static void DoAddMonitor()
{
    if (!g_monPathEdit) return;
    std::wstring path = g_monPathEdit->text().toStdWString();
    if (path.empty()) {
        QString dir = QFileDialog::getExistingDirectory(
            g_mainWnd, "Выберите директорию для мониторинга");
        if (dir.isEmpty()) return;
        path = dir.toStdWString();
        g_monPathEdit->setText(dir);
    }
    int rc = RpcAddMonitorDirectory(path);
    if (rc == RBPO_ERR_NO_LICENSE) {
        QMessageBox::warning(g_mainWnd, "Мониторинг", "Требуется активная лицензия"); return;
    }
    QMessageBox::information(g_mainWnd, "Мониторинг",
        rc == RBPO_OK ? ("Мониторинг запущен:\n" + W(path)) : "Ошибка связи со службой");
}

static void DoRemoveMonitor()
{
    if (!g_monPathEdit) return;
    std::wstring path = g_monPathEdit->text().toStdWString();
    if (path.empty()) return;
    int rc = RpcRemoveMonitorDirectory(path);
    QMessageBox::information(g_mainWnd, "Мониторинг",
        rc == RBPO_OK ? ("Мониторинг остановлен:\n" + W(path)) : "Ошибка связи со службой");
}

static void DoGetMonitorResults()
{
    std::wstring results;
    int rc = RpcGetMonitorResults(results);
    if (rc != RBPO_OK) {
        QMessageBox::critical(g_mainWnd, "Мониторинг", "Ошибка связи со службой"); return;
    }
    if (results == L"No threats detected")
        QMessageBox::information(g_mainWnd, "Угрозы не обнаружены (мониторинг)", W(results));
    else
        QMessageBox::warning(g_mainWnd, "Обнаружены угрозы (мониторинг)", W(results));
}

// ---------------------------------------------------------------------------
// Entry point (Qt6::EntryPoint bridges WinMain → main)
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    Log("=== rbpo-app started (PID=%u) ===", GetCurrentProcessId());

    if (!IsServiceRunning()) StartServiceAndWait();

    g_hMutex = CreateMutexW(nullptr, TRUE, APP_MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (g_hMutex) CloseHandle(g_hMutex);
        return 0;
    }

    QApplication app(argc, argv);
    app.setApplicationName("РБПО Антивирус");
    app.setOrganizationName("RBPO");
    app.setStyle("Fusion");
    app.setQuitOnLastWindowClosed(false);

    QIcon appIcon(":/logo.ico");
    if (appIcon.isNull())
        appIcon = app.style()->standardIcon(QStyle::SP_ComputerIcon);
    app.setWindowIcon(appIcon);

    // Main window with stacked pages
    g_mainWnd = new QMainWindow();
    g_mainWnd->setWindowTitle("РБПО — Антивирус");
    g_mainWnd->setMinimumSize(580, 480);
    g_mainWnd->resize(640, 540);
    g_mainWnd->setWindowIcon(appIcon);

    g_stack = new QStackedWidget();
    g_mainWnd->setCentralWidget(g_stack);
    g_stack->addWidget(BuildLoginPage());    // index 0
    g_stack->addWidget(BuildActivatePage()); // index 1
    g_stack->addWidget(BuildLicensedPage()); // index 2

    g_mainWnd->installEventFilter(new HideOnClose());

    // Tray icon
    g_tray = new QSystemTrayIcon(appIcon, &app);
    g_tray->setToolTip("РБПО Антивирус");
    QMenu* trayMenu = new QMenu();
    trayMenu->addAction("Открыть", []{
        g_mainWnd->show(); g_mainWnd->raise(); g_mainWnd->activateWindow(); RefreshUI();
    });
    trayMenu->addSeparator();
    trayMenu->addAction("Выход", []{
        StopServiceViaRpc();
        UnbindRpc();
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
        QApplication::quit();
    });
    g_tray->setContextMenu(trayMenu);
    QObject::connect(g_tray, &QSystemTrayIcon::activated,
        [](QSystemTrayIcon::ActivationReason r){
            if (r == QSystemTrayIcon::Trigger) {
                g_mainWnd->show(); g_mainWnd->raise(); g_mainWnd->activateWindow(); RefreshUI();
            }
        });
    g_tray->show();

    // Poll timer — refreshes visible window every 5 s
    QTimer* pollTimer = new QTimer(&app);
    QObject::connect(pollTimer, &QTimer::timeout, []{
        if (g_mainWnd && g_mainWnd->isVisible()) RefreshUI();
    });
    pollTimer->start(5000);

    BindRpc();
    RefreshUI();

    if (!app.arguments().contains("--silent"))
        g_mainWnd->show();

    int ret = app.exec();
    UnbindRpc();
    ReleaseMutex(g_hMutex);
    CloseHandle(g_hMutex);
    return ret;
}
