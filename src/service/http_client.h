#pragma once
#include <string>

namespace rbpo {

struct HttpResponse {
    int  status = 0;
    std::string body;
    bool transportError = false;
};

/* POST/GET JSON через WinHTTP. TLS при RBPO_BACKEND_USE_TLS=1 (как у товарища); иначе HTTP. */
HttpResponse HttpsRequest(const std::wstring& host, int port,
                          const std::wstring& method,
                          const std::wstring& path,
                          const std::string&  jsonBody,
                          const std::string&  bearerToken = "");

/* Resolve backend host/port (env override → defaults). */
void GetBackend(std::wstring& host, int& port);

} // namespace rbpo
