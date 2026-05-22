#pragma once

#define RBPO_SERVICE_NAME       L"RBPOService"
#define RBPO_SERVICE_DISPLAY    L"RBPO Service"
#define RBPO_RPC_ENDPOINT       L"RBPOServiceEndpoint"
#define RBPO_APP_EXE_NAME       L"rbpo-app.exe"
#define RBPO_SERVICE_EXE_NAME   L"rbpo-service.exe"

/*
 * rbpo_backend (Spring): server.port 8081, SSL опционально (см. application.properties).
 * Переопределение: RBPO_BACKEND_HOST / RBPO_BACKEND_PORT.
 */
/* Spring на Mac, доступен с Windows-клиента через ZeroTier-сеть. */
#define RBPO_BACKEND_HOST_DEFAULT  L"10.88.216.221"
#define RBPO_BACKEND_PORT_DEFAULT    8081
/* HTTPS при RBPO_BACKEND_USE_TLS=1; для rbpo_backend без SSL — 0 (по умолчанию). */
#define RBPO_BACKEND_USE_TLS_DEFAULT 0

/* Совпадает с jwt.* когда в теле login/refresh нет expiresIn — только accessToken/refreshToken. */
#define RBPO_ACCESS_TTL_MS_DEFAULT   900000LL
#define RBPO_REFRESH_TTL_MS_DEFAULT 604800000LL

#define RBPO_OK                   0
#define RBPO_ERR_GENERIC          1
#define RBPO_ERR_NETWORK          2
#define RBPO_ERR_AUTH             3
#define RBPO_ERR_NOT_AUTH         4
#define RBPO_ERR_NO_LICENSE       5
#define RBPO_ERR_BACKEND          6
#define RBPO_ERR_BAD_INPUT        7
