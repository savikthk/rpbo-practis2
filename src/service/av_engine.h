#pragma once
#include <windows.h>
#include <map>
#include <vector>
#include <string>
#include <cstdint>

namespace rbpo {

enum class AvObjectType : uint8_t {
    PE     = 0,
    Script = 1,
};

struct AvRecord {
    uint64_t             prefix;
    uint32_t             sigLen;
    std::vector<uint8_t> sigHash;
    int64_t              offsetBegin;
    int64_t              offsetEnd;
    AvObjectType         type;
    std::vector<uint8_t> recordSig;
    std::vector<uint8_t> sigBytes;
    bool                 hasRemainderHash = false;
    std::wstring         threatName;
    std::string          id;
    std::vector<uint8_t> rsaSig;
};

struct AvDbInfo {
    std::wstring date;
    uint32_t     count;
};

void         AvLoad();
void         AvLoadFromBackend(const std::string& accessToken);
void         AvShutdown();
AvDbInfo     AvGetInfo();
bool         AvScanFile(const std::wstring& path, std::wstring& threatName);
std::wstring AvScanDirectory(const std::wstring& dirPath);
std::wstring AvScanAllDrives();

void         AvSetSchedule(const std::wstring& path, long intervalSeconds);
void         AvClearSchedule();
std::wstring AvGetScheduleResults(int64_t& lastScanTimeUnix);

void         AvAddMonitorDirectory(const std::wstring& path);
void         AvRemoveMonitorDirectory(const std::wstring& path);
std::wstring AvGetMonitorResults();

void         AvDbStartUpdate(long intervalSeconds);
void         AvDbStopUpdate();

} // namespace rbpo
