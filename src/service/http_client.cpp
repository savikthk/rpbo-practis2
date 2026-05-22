#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <vector>
#include <string>
#include <cstdlib>

#include "http_client.h"
#include "rbpo_rpc_constants.h"

#pragma comment(lib, "winhttp.lib")

namespace rbpo {

namespace {

static std::wstring Utf8ToWide(const char* s) {
    if (!s) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w.data(), n);
    return w;
}

static bool BackendUseTls() {
    wchar_t buf[16] = {};
    DWORD n = GetEnvironmentVariableW(L"RBPO_BACKEND_USE_TLS", buf, 16);
    if (n > 0)
        return buf[0] == L'1';
    return RBPO_BACKEND_USE_TLS_DEFAULT != 0;
}

} // namespace

void GetBackend(std::wstring& host, int& port) {
    host = RBPO_BACKEND_HOST_DEFAULT;
    port = RBPO_BACKEND_PORT_DEFAULT;

    wchar_t buf[256] = {};
    DWORD n = GetEnvironmentVariableW(L"RBPO_BACKEND_HOST", buf, 256);
    if (n > 0 && n < 256) host = buf;

    n = GetEnvironmentVariableW(L"RBPO_BACKEND_PORT", buf, 256);
    if (n > 0 && n < 256) {
        int p = _wtoi(buf);
        if (p > 0) port = p;
    }
}

HttpResponse HttpsRequest(const std::wstring& host, int port,
                          const std::wstring& method,
                          const std::wstring& path,
                          const std::string&  jsonBody,
                          const std::string&  bearerToken)
{
    HttpResponse out;
    const bool useTls = BackendUseTls();

    HINTERNET hSession = WinHttpOpen(L"RBPO-Service/1.0",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        out.transportError = true;
        return out;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(),
                                        static_cast<INTERNET_PORT>(port), 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        out.transportError = true;
        return out;
    }

    const DWORD flags = useTls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        out.transportError = true;
        return out;
    }

    if (useTls) {
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
    }

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearerToken.empty()) {
        headers += L"Authorization: Bearer " + Utf8ToWide(bearerToken.c_str()) + L"\r\n";
    }

    BOOL ok = WinHttpSendRequest(hRequest,
                                 headers.c_str(),
                                 static_cast<DWORD>(-1),
                                 jsonBody.empty() ? WINHTTP_NO_REQUEST_DATA
                                                  : (LPVOID)jsonBody.data(),
                                 static_cast<DWORD>(jsonBody.size()),
                                 static_cast<DWORD>(jsonBody.size()),
                                 0);
    if (!ok) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        out.transportError = true;
        return out;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        out.transportError = true;
        return out;
    }

    DWORD statusCode = 0;
    DWORD szLen = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode,
                        &szLen, WINHTTP_NO_HEADER_INDEX);
    out.status = static_cast<int>(statusCode);

    DWORD avail = 0;
    do {
        avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        std::vector<char> chunk(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, chunk.data(), avail, &read)) break;
        out.body.append(chunk.data(), read);
    } while (avail > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return out;
}

} // namespace rbpo
