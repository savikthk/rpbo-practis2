#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <ctime>
#include <cstdio>
#include <vector>

#include "state.h"
#include "http_client.h"
#include "json_util.h"
#include "rbpo_rpc_constants.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")

namespace rbpo {

extern "C" void RBPOLog(const char* fmt, ...); // implemented in service_main.cpp

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------
static std::mutex g_mtx;

static std::string g_accessToken;
static std::string g_refreshToken;
static long long   g_accessExpiresAtMs   = 0;   // unix ms
static long long   g_refreshExpiresAtMs  = 0;
static std::string g_email;
static std::string g_name;

static bool        g_ticketHeld          = false;
static std::string g_ticketExpirationIso;
static bool        g_ticketBlocked       = false; // admin-blocked
static bool        g_ticketExpired       = false; // expired naturally
static long long   g_ticketExpiresAtMs   = 0;
static std::string g_productId;          // remembered across logout; persisted to registry

static HANDLE      g_wakeEvent           = nullptr;
static std::atomic<bool> g_stopWorkers{false};
static std::thread g_tokenWorker;
static std::thread g_licenseWorker;

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------
static long long NowMs() {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    /* FILETIME = 100ns since 1601; convert to unix ms. */
    const long long EPOCH_DIFF = 116444736000000000LL;
    return (long long)((u.QuadPart - EPOCH_DIFF) / 10000ULL);
}

/* Ticket.expiryDate (Spring Instant, ISO-8601). Совместимо с expirationDate из других бэкендов. */
static long long ParseIsoToMs(const std::string& isoRaw) {
    if (isoRaw.empty()) return 0;
    std::string iso = isoRaw;
    if (!iso.empty() && (iso.back() == 'Z' || iso.back() == 'z')) iso.pop_back();
    size_t dot = iso.find('.');
    if (dot != std::string::npos) iso = iso.substr(0, dot);
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, sec = 0;
    if (sscanf_s(iso.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &sec) != 6) {
        if (sscanf_s(iso.c_str(), "%d-%d-%dT%d:%d", &y, &mo, &d, &h, &mi) != 5) return 0;
        sec = 0;
    }
    SYSTEMTIME st = {};
    st.wYear = (WORD)y; st.wMonth = (WORD)mo; st.wDay = (WORD)d;
    st.wHour = (WORD)h; st.wMinute = (WORD)mi; st.wSecond = (WORD)sec;
    FILETIME ftLocal, ftUtc;
    if (!SystemTimeToFileTime(&st, &ftLocal)) return 0;
    if (!LocalFileTimeToFileTime(&ftLocal, &ftUtc)) return 0;
    ULARGE_INTEGER u; u.LowPart = ftUtc.dwLowDateTime; u.HighPart = ftUtc.dwHighDateTime;
    const long long EPOCH_DIFF = 116444736000000000LL;
    return (long long)((u.QuadPart - EPOCH_DIFF) / 10000ULL);
}

// ---------------------------------------------------------------------------
// Registry persistence for productId
// (service runs as LocalSystem, so HKLM\SOFTWARE\RBPO is writable)
// ---------------------------------------------------------------------------
static const wchar_t* RBPO_REG_KEY  = L"SOFTWARE\\RBPO";
static const wchar_t* RBPO_REG_PID  = L"ProductId";

static void SaveProductIdToRegistry(const std::string& pid) {
    if (pid.empty()) return;
    HKEY hKey;
    LONG res = RegCreateKeyExW(HKEY_LOCAL_MACHINE, RBPO_REG_KEY,
                               0, nullptr, REG_OPTION_NON_VOLATILE,
                               KEY_SET_VALUE, nullptr, &hKey, nullptr);
    if (res != ERROR_SUCCESS) return;
    auto wide = Utf8ToWide(pid);
    RegSetValueExW(hKey, RBPO_REG_PID, 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(wide.c_str()),
                   static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
}

static std::string LoadProductIdFromRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RBPO_REG_KEY,
                      0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return "";
    wchar_t buf[128] = {};
    DWORD size = sizeof(buf);
    DWORD type = REG_SZ;
    LONG res = RegQueryValueExW(hKey, RBPO_REG_PID,
                                nullptr, &type,
                                reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hKey);
    if (res != ERROR_SUCCESS || type != REG_SZ) return "";
    return WideToUtf8(buf);
}

// ---------------------------------------------------------------------------
// MAC address detection (first non-loopback adapter with valid MAC)
// ---------------------------------------------------------------------------
static std::string GetDeviceMac() {
    ULONG bufLen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &bufLen);
    if (bufLen == 0) return "00:00:00:00:00:00";
    std::vector<BYTE> buf(bufLen);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &bufLen) != ERROR_SUCCESS)
        return "00:00:00:00:00:00";
    /* Pick the adapter with the lowest IfIndex (stable across reboots, ignores
     * VPN/loopback/zero-MAC adapters). Don't filter by OperStatus — the user's
     * primary adapter may be temporarily down but we still want a stable id. */
    IP_ADAPTER_ADDRESSES* best = nullptr;
    for (auto* a = addrs; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (a->PhysicalAddressLength != 6) continue;
        bool allZero = true;
        for (int i = 0; i < 6; i++)
            if (a->PhysicalAddress[i]) { allZero = false; break; }
        if (allZero) continue;
        if (!best || a->IfIndex < best->IfIndex) best = a;
    }
    if (!best) return "00:00:00:00:00:00";
    char mac[18];
    sprintf_s(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
              best->PhysicalAddress[0], best->PhysicalAddress[1], best->PhysicalAddress[2],
              best->PhysicalAddress[3], best->PhysicalAddress[4], best->PhysicalAddress[5]);
    RBPOLog("GetDeviceMac → %s (IfIndex=%lu)", mac, best->IfIndex);
    return mac;
}

static std::string GetProductId() {
    /* Priority: in-memory → registry → env var.
     * In-memory is set from activation/check responses and persisted to registry,
     * so after a service restart the registry copy is loaded by StateInit(). */
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!g_productId.empty()) return g_productId;
    }
    wchar_t buf[128] = {};
    DWORD n = GetEnvironmentVariableW(L"RBPO_PRODUCT_ID", buf, 128);
    if (n > 0 && n < 128) return WideToUtf8(buf);
    return "";
}

// ---------------------------------------------------------------------------
// JWT email extractor — parses payload base64url to find "sub" or "email"
// (used as a fallback if /auth/me fails)
// ---------------------------------------------------------------------------
static std::string Base64UrlDecode(const std::string& in) {
    std::string s = in;
    for (auto& c : s) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    while (s.size() % 4) s += '=';
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(s.c_str(), 0, CRYPT_STRING_BASE64,
                              nullptr, &outLen, nullptr, nullptr)) return "";
    std::string out(outLen, '\0');
    if (!CryptStringToBinaryA(s.c_str(), 0, CRYPT_STRING_BASE64,
                              (BYTE*)out.data(), &outLen, nullptr, nullptr)) return "";
    out.resize(outLen);
    return out;
}

static std::string JwtExtract(const std::string& jwt, const std::string& key) {
    size_t p1 = jwt.find('.');
    if (p1 == std::string::npos) return "";
    size_t p2 = jwt.find('.', p1 + 1);
    if (p2 == std::string::npos) return "";
    std::string payload = Base64UrlDecode(jwt.substr(p1 + 1, p2 - p1 - 1));
    return JsonExtractString(payload, key);
}

static long long JwtExpUnixMs(const std::string& jwt) {
    size_t p1 = jwt.find('.');
    if (p1 == std::string::npos) return 0;
    size_t p2 = jwt.find('.', p1 + 1);
    if (p2 == std::string::npos) return 0;
    std::string payload = Base64UrlDecode(jwt.substr(p1 + 1, p2 - p1 - 1));
    long long expSec = JsonExtractNumber(payload, "exp");
    if (expSec <= 0) return 0;
    return expSec * 1000;
}

// ---------------------------------------------------------------------------
// Backend calls (no locks held)
// ---------------------------------------------------------------------------
static int CallLogin(const std::string& email, const std::string& password,
                     std::string& accessOut, std::string& refreshOut,
                     long long& accessExpMsOut, long long& refreshExpMsOut,
                     std::string& errOut)
{
    std::wstring host; int port;
    GetBackend(host, port);

    /* ru.rbpo.backend: LoginRequest — username, password (как email/логин в UI). */
    std::string body = "{\"username\":\"" + JsonEscape(email) +
                       "\",\"password\":\"" + JsonEscape(password) + "\"}";
    auto resp = HttpsRequest(host, port, L"POST", L"/api/auth/login", body);
    if (resp.transportError) { errOut = "Network error"; return RBPO_ERR_NETWORK; }
    if (resp.status / 100 != 2) {
        errOut = "Login failed (HTTP " + std::to_string(resp.status) + ")";
        std::string m = JsonExtractString(resp.body, "message");
        if (!m.empty()) errOut = m;
        return RBPO_ERR_AUTH;
    }
    accessOut  = JsonExtractString(resp.body, "accessToken");
    refreshOut = JsonExtractString(resp.body, "refreshToken");
    if (accessOut.empty() || refreshOut.empty()) {
        errOut = "Malformed login response";
        return RBPO_ERR_BACKEND;
    }
    long long now = NowMs();
    long long aRel = JsonExtractNumber(resp.body, "accessTokenExpiresIn");
    long long rRel = JsonExtractNumber(resp.body, "refreshTokenExpiresIn");
    long long aMs = (aRel > 0) ? (now + aRel) : JwtExpUnixMs(accessOut);
    long long rMs = (rRel > 0) ? (now + rRel) : JwtExpUnixMs(refreshOut);
    if (aMs <= 0) aMs = now + RBPO_ACCESS_TTL_MS_DEFAULT;
    if (rMs <= 0) rMs = now + RBPO_REFRESH_TTL_MS_DEFAULT;
    accessExpMsOut  = aMs;
    refreshExpMsOut = rMs;
    return RBPO_OK;
}

static int CallRefresh(const std::string& refreshToken,
                       std::string& accessOut, std::string& refreshOut,
                       long long& accessExpMsOut, long long& refreshExpMsOut)
{
    std::wstring host; int port;
    GetBackend(host, port);
    std::string body = "{\"refreshToken\":\"" + JsonEscape(refreshToken) + "\"}";
    auto resp = HttpsRequest(host, port, L"POST", L"/api/auth/refresh", body);
    if (resp.transportError || resp.status / 100 != 2) return RBPO_ERR_NETWORK;
    accessOut  = JsonExtractString(resp.body, "accessToken");
    refreshOut = JsonExtractString(resp.body, "refreshToken");
    if (accessOut.empty()) return RBPO_ERR_BACKEND;
    long long now = NowMs();
    long long aRel = JsonExtractNumber(resp.body, "accessTokenExpiresIn");
    long long rRel = JsonExtractNumber(resp.body, "refreshTokenExpiresIn");
    long long aMs = (aRel > 0) ? (now + aRel) : JwtExpUnixMs(accessOut);
    long long rMs = (rRel > 0) ? (now + rRel) : JwtExpUnixMs(refreshOut);
    if (aMs <= 0) aMs = now + RBPO_ACCESS_TTL_MS_DEFAULT;
    if (rMs <= 0) rMs = now + RBPO_REFRESH_TTL_MS_DEFAULT;
    accessExpMsOut  = aMs;
    refreshExpMsOut = rMs;
    return RBPO_OK;
}

static void CallLogoutBackend(const std::string&) {
    /* В rbpo_backend нет POST /api/auth/logout — как у товарище с токен-ревокацией несовместимо. */
}

static int CallMe(const std::string& accessToken,
                  std::string& email, std::string& name)
{
    std::wstring host; int port;
    GetBackend(host, port);
    auto resp = HttpsRequest(host, port, L"GET", L"/api/auth/me", "", accessToken);
    if (resp.transportError) return RBPO_ERR_NETWORK;
    if (resp.status / 100 != 2) return RBPO_ERR_AUTH;
    email = JsonExtractString(resp.body, "email");
    std::string fn = JsonExtractString(resp.body, "firstName");
    std::string ln = JsonExtractString(resp.body, "lastName");
    name = fn;
    if (!ln.empty()) {
        if (!name.empty()) name += " ";
        name += ln;
    }
    if (name.empty())
        name = JsonExtractString(resp.body, "username");
    return RBPO_OK;
}

/* Parse SignedTicketResponse: { "ticket": { ...TicketResponse... }, "signature": "..." } */
static bool ParseSignedTicket(const std::string& body,
                              std::string& expIsoOut, bool& blockedOut,
                              std::string& productIdOut)
{
    size_t p = body.find("\"ticket\"");
    if (p == std::string::npos) return false;
    size_t braceStart = body.find('{', p);
    if (braceStart == std::string::npos) return false;
    int depth = 0;
    size_t i = braceStart;
    for (; i < body.size(); i++) {
        if (body[i] == '{') depth++;
        else if (body[i] == '}') { depth--; if (depth == 0) { i++; break; } }
    }
    std::string ticket = body.substr(braceStart, i - braceStart);
    expIsoOut    = JsonExtractString(ticket, "expiryDate");
    if (expIsoOut.empty())
        expIsoOut = JsonExtractString(ticket, "expirationDate");
    blockedOut   = JsonExtractBool(ticket, "blocked", false);
    productIdOut = JsonExtractString(ticket, "productId");
    return !expIsoOut.empty();
}

static int CallCheckLicense(const std::string& accessToken,
                            std::string& expIsoOut, bool& blockedOut,
                            int& httpStatusOut)
{
    std::wstring host; int port;
    GetBackend(host, port);
    std::string mac = GetDeviceMac();
    std::string pid = GetProductId();
    if (pid.empty()) {
        /* Backend rejects empty productId with 400. Skip the call entirely
         * — the user has not configured RBPO_PRODUCT_ID. */
        RBPOLog("CheckLicense skipped: RBPO_PRODUCT_ID not set");
        httpStatusOut = 0;
        return RBPO_ERR_NO_LICENSE;
    }
    std::string body = "{\"deviceMac\":\"" + JsonEscape(mac) +
                       "\",\"productId\":" + pid + "}";
    auto resp = HttpsRequest(host, port, L"POST", L"/api/licenses/check", body, accessToken);
    httpStatusOut = resp.status;
    RBPOLog("CheckLicense HTTP %d body=%.200s", resp.status, resp.body.c_str());
    if (resp.transportError) return RBPO_ERR_NETWORK;
    if (resp.status == 404)  return RBPO_ERR_NO_LICENSE;
    if (resp.status == 403)  { blockedOut = true; return RBPO_ERR_NO_LICENSE; }
    if (resp.status / 100 != 2) return RBPO_ERR_BACKEND;
    std::string newProductId;
    if (!ParseSignedTicket(resp.body, expIsoOut, blockedOut, newProductId)) return RBPO_ERR_BACKEND;
    if (!newProductId.empty()) {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_productId != newProductId) {
            g_productId = newProductId;
            SaveProductIdToRegistry(newProductId);
        }
    }
    return RBPO_OK;
}

static int CallActivate(const std::string& accessToken, const std::string& key,
                        std::string& expIsoOut, bool& blockedOut, std::string& errOut)
{
    std::wstring host; int port;
    GetBackend(host, port);
    std::string mac = GetDeviceMac();
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD hostnameLen = sizeof(hostname);
    GetComputerNameA(hostname, &hostnameLen);
    std::string deviceName = hostname[0] ? hostname : "Windows-PC";
    std::string body = "{\"activationKey\":\"" + JsonEscape(key) +
                       "\",\"deviceMac\":\"" + JsonEscape(mac) +
                       "\",\"deviceName\":\"" + JsonEscape(deviceName) + "\"}";
    auto resp = HttpsRequest(host, port, L"POST", L"/api/licenses/activate", body, accessToken);
    if (resp.transportError) { errOut = "Network error"; return RBPO_ERR_NETWORK; }
    if (resp.status / 100 != 2) {
        std::string m = JsonExtractString(resp.body, "message");
        errOut = m.empty() ? ("Activation failed (HTTP " + std::to_string(resp.status) + ")") : m;
        return RBPO_ERR_BACKEND;
    }
    /* Per spec: if activation does not return ticket, fall back to /check. */
    std::string newProductId;
    if (!ParseSignedTicket(resp.body, expIsoOut, blockedOut, newProductId)) {
        int httpStatus = 0;
        return CallCheckLicense(accessToken, expIsoOut, blockedOut, httpStatus);
    }
    if (!newProductId.empty()) {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_productId != newProductId) {
            g_productId = newProductId;
            SaveProductIdToRegistry(newProductId);
        }
    }
    return RBPO_OK;
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------
static void WaitOrStop(long long ms) {
    if (ms < 1000) ms = 1000;
    if (ms > 600000) ms = 600000;
    WaitForSingleObject(g_wakeEvent, (DWORD)ms);
}

static void TokenWorker() {
    RBPOLog("TokenWorker started");
    while (!g_stopWorkers) {
        long long sleepMs = 60000;
        std::string refresh;
        long long  accessExp = 0, refreshExp = 0;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            refresh    = g_refreshToken;
            accessExp  = g_accessExpiresAtMs;
            refreshExp = g_refreshExpiresAtMs;
        }
        if (refresh.empty()) { WaitOrStop(60000); continue; }

        long long now = NowMs();
        /* Refresh 60s before access expires, or immediately if already past. */
        long long until = accessExp - now - 60000;
        if (until > 0) { WaitOrStop(until); continue; }

        /* Refresh-token still valid? If refresh-token expired, force logout. */
        if (refreshExp > 0 && now >= refreshExp) {
            RBPOLog("Refresh token expired — forcing logout");
            Logout();
            continue;
        }

        std::string newAccess, newRefresh;
        long long newAccessExp = 0, newRefreshExp = 0;
        int rc = CallRefresh(refresh, newAccess, newRefresh, newAccessExp, newRefreshExp);
        if (rc == RBPO_OK) {
            std::lock_guard<std::mutex> lk(g_mtx);
            g_accessToken = newAccess;
            if (!newRefresh.empty()) g_refreshToken = newRefresh;
            g_accessExpiresAtMs = newAccessExp;
            if (newRefreshExp > 0) g_refreshExpiresAtMs = newRefreshExp;
            RBPOLog("Tokens refreshed");
        } else {
            RBPOLog("Token refresh failed rc=%d, retry in 30s", rc);
            WaitOrStop(30000);
        }
    }
    RBPOLog("TokenWorker stopped");
}

static void LicenseWorker() {
    RBPOLog("LicenseWorker started");
    while (!g_stopWorkers) {
        /* Poll every 5 seconds. WaitOrStop wakes early if g_wakeEvent is set
         * (e.g. on login/logout), so the first check after login is immediate. */
        WaitOrStop(5000);
        if (g_stopWorkers) break;

        std::string access;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            access = g_accessToken;
        }
        if (access.empty()) continue;

        std::string expIso; bool blocked = false; int httpStatus = 0;
        int rc = CallCheckLicense(access, expIso, blocked, httpStatus);

        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_accessToken.empty()) continue; // logged out during HTTP call
        if (rc == RBPO_OK) {
            g_ticketExpirationIso = expIso;
            g_ticketBlocked  = blocked;
            g_ticketExpired  = false;
            g_ticketExpiresAtMs = ParseIsoToMs(expIso);
            g_ticketHeld = true;
            RBPOLog("License OK exp=%s blocked=%d", expIso.c_str(), (int)blocked);
        } else if (rc == RBPO_ERR_NO_LICENSE) {
            bool wasHeld       = g_ticketHeld;
            long long storedExp = g_ticketExpiresAtMs;
            g_ticketHeld        = false;
            g_ticketExpiresAtMs = 0;
            if (wasHeld || blocked) {
                /* Distinguish blocked vs expired:
                 * If the stored expiration has already passed → expired naturally.
                 * If there was still time left → admin blocked it. */
                if (storedExp > 0 && storedExp < NowMs()) {
                    g_ticketExpired = true;
                    g_ticketBlocked = false;
                    RBPOLog("License EXPIRED (was due %lld ms ago)", NowMs() - storedExp);
                } else {
                    g_ticketExpired = false;
                    g_ticketBlocked = true;
                    RBPOLog("License BLOCKED by admin (had %lld ms left)", storedExp - NowMs());
                }
            } else {
                g_ticketBlocked = false;
                g_ticketExpired = false;
                g_ticketExpirationIso.clear();
                RBPOLog("License absent http=%d", httpStatus);
            }
        } else {
            RBPOLog("License check failed rc=%d http=%d", rc, httpStatus);
        }
    }
    RBPOLog("LicenseWorker stopped");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
void StateInit() {
    /* Restore productId from registry so /check works on first login after restart. */
    std::string regPid = LoadProductIdFromRegistry();
    if (!regPid.empty()) {
        g_productId = regPid;
        RBPOLog("Loaded productId from registry: %s", regPid.c_str());
    }
    g_wakeEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_stopWorkers = false;
    g_tokenWorker   = std::thread(TokenWorker);
    g_licenseWorker = std::thread(LicenseWorker);
}

void StateShutdown() {
    g_stopWorkers = true;
    if (g_wakeEvent) SetEvent(g_wakeEvent);
    if (g_tokenWorker.joinable())   g_tokenWorker.join();
    if (g_licenseWorker.joinable()) g_licenseWorker.join();
    if (g_wakeEvent) { CloseHandle(g_wakeEvent); g_wakeEvent = nullptr; }

    std::lock_guard<std::mutex> lk(g_mtx);
    g_accessToken.clear(); g_refreshToken.clear();
    g_email.clear(); g_name.clear();
    g_ticketHeld = false;
    g_ticketExpirationIso.clear();
}

UserInfo GetUserInfo() {
    UserInfo u;
    std::lock_guard<std::mutex> lk(g_mtx);
    u.authenticated = !g_accessToken.empty();
    u.email = g_email;
    u.name  = g_name;
    return u;
}

LicenseInfo GetLicenseInfo() {
    LicenseInfo l;
    std::lock_guard<std::mutex> lk(g_mtx);
    l.held          = g_ticketHeld;
    l.expirationIso = g_ticketExpirationIso;
    l.blocked       = g_ticketBlocked;
    l.expired       = g_ticketExpired;
    if (g_ticketExpiresAtMs > 0) {
        l.secondsLeft = (g_ticketExpiresAtMs - NowMs()) / 1000;
    }
    return l;
}

std::string StateGetAccessToken() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_accessToken;
}

int Login(const std::wstring& email, const std::wstring& password,
          std::wstring& errorMessage)
{
    std::string e8 = WideToUtf8(email), p8 = WideToUtf8(password);
    std::string access, refresh; long long aExp, rExp; std::string err;
    int rc = CallLogin(e8, p8, access, refresh, aExp, rExp, err);
    if (rc != RBPO_OK) { errorMessage = Utf8ToWide(err); return rc; }

    std::string mEmail, mName;
    int rcMe = CallMe(access, mEmail, mName);
    if (rcMe != RBPO_OK) {
        mEmail = JwtExtract(access, "sub");
        if (mEmail.empty()) mEmail = e8;
    }

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_accessToken = access;
        g_refreshToken = refresh;
        g_accessExpiresAtMs = aExp;
        g_refreshExpiresAtMs = rExp;
        g_email = mEmail;
        g_name  = mName;
    }
    SetEvent(g_wakeEvent);

    /* Kick off initial license check (best-effort, non-fatal). */
    std::string expIso; bool blocked = false; int httpStatus = 0;
    int rcLic = CallCheckLicense(access, expIso, blocked, httpStatus);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (rcLic == RBPO_OK) {
            g_ticketExpirationIso = expIso;
            g_ticketBlocked = blocked;
            g_ticketExpired = false;
            g_ticketExpiresAtMs = ParseIsoToMs(expIso);
            g_ticketHeld = true;
        } else {
            g_ticketHeld = false;
            g_ticketExpirationIso.clear();
            g_ticketExpiresAtMs = 0;
            g_ticketExpired = false;
            g_ticketBlocked = blocked; // 403 → blocked even without ticket
        }
    }
    SetEvent(g_wakeEvent);
    return RBPO_OK;
}

int Logout() {
    std::string refresh;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        refresh = g_refreshToken;
        g_accessToken.clear();
        g_refreshToken.clear();
        g_accessExpiresAtMs = 0;
        g_refreshExpiresAtMs = 0;
        g_email.clear();
        g_name.clear();
        g_ticketHeld = false;
        g_ticketExpirationIso.clear();
        g_ticketExpiresAtMs = 0;
        g_ticketBlocked = false;
        g_ticketExpired = false;
    }
    if (!refresh.empty()) CallLogoutBackend(refresh);
    SetEvent(g_wakeEvent);
    return RBPO_OK;
}

int Activate(const std::wstring& activationKey, std::wstring& errorMessage) {
    std::string access;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        access = g_accessToken;
    }
    if (access.empty()) { errorMessage = L"Not authenticated"; return RBPO_ERR_NOT_AUTH; }

    std::string key8 = WideToUtf8(activationKey);
    std::string expIso; bool blocked = false; std::string err;
    int rc = CallActivate(access, key8, expIso, blocked, err);
    if (rc != RBPO_OK) { errorMessage = Utf8ToWide(err); return rc; }

    std::lock_guard<std::mutex> lk(g_mtx);
    g_ticketExpirationIso = expIso;
    g_ticketBlocked = blocked;
    g_ticketExpired = false;
    g_ticketExpiresAtMs = ParseIsoToMs(expIso);
    g_ticketHeld = true;
    SetEvent(g_wakeEvent);
    return RBPO_OK;
}

int LicenseGate() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_ticketHeld ? RBPO_OK : RBPO_ERR_NO_LICENSE;
}

} // namespace rbpo
