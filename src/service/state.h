#pragma once
#include <string>

namespace rbpo {

struct UserInfo {
    bool        authenticated = false;
    std::string email;
    std::string name;
};

struct LicenseInfo {
    bool        held = false;
    std::string expirationIso; // "yyyy-MM-ddTHH:mm"
    bool        blocked = false; // admin-blocked (time still valid when blocked)
    bool        expired = false; // license expired naturally
    long long   secondsLeft = 0;
};

/* Initialize background-worker engine (call once from ServiceMain). */
void StateInit();
void StateShutdown();

/* Snapshot getters (thread-safe, copy-out). */
UserInfo    GetUserInfo();
LicenseInfo GetLicenseInfo();

/* Sync operations. Return RBPO_OK or error code; populate errorMessage on failure. */
int Login   (const std::wstring& email, const std::wstring& password,
             std::wstring& errorMessage);
int Logout  ();
int Activate(const std::wstring& activationKey, std::wstring& errorMessage);

/* Used by license-gated RPC: returns RBPO_OK if a ticket is held, else RBPO_ERR_NO_LICENSE. */
int LicenseGate();

/* Returns a copy of the current access token (empty string if not authenticated). */
std::string StateGetAccessToken();

} // namespace rbpo
