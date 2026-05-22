#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <map>
#include <queue>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <ctime>
#include "av_engine.h"
#include "av_db_io.h"
#include "http_client.h"
#include "json_util.h"
#include "state.h"

#pragma comment(lib, "bcrypt.lib")

namespace rbpo {

extern "C" void RBPOLog(const char* fmt, ...);

static std::vector<uint8_t> Sha256(const void* data, size_t len)
{
    std::vector<uint8_t> result(32, 0);
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return result;
    DWORD objSz = 0, copied = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objSz, sizeof(DWORD), &copied, 0);
    std::vector<uint8_t> obj(objSz);
    if (BCryptCreateHash(hAlg, &hHash, obj.data(), objSz, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }
    BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    BCryptFinishHash(hHash, result.data(), (ULONG)result.size(), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

static std::map<uint64_t, std::vector<AvRecord>> g_db;
static std::vector<AvRecord> g_allRecords;
static std::wstring g_dbDate;
static uint32_t     g_dbCount = 0;
static std::mutex   g_dbMtx;

static std::vector<uint8_t> ComputeRecordSig(const AvRecord& r)
{
    std::vector<uint8_t> buf;
    buf.reserve(8 + 4 + r.sigHash.size() + 8 + 8 + 1);
    for (int i = 0; i < 8; i++)
        buf.push_back((uint8_t)((r.prefix >> (i * 8)) & 0xFF));
    for (int i = 0; i < 4; i++)
        buf.push_back((uint8_t)((r.sigLen >> (i * 8)) & 0xFF));
    buf.insert(buf.end(), r.sigHash.begin(), r.sigHash.end());
    for (int i = 0; i < 8; i++)
        buf.push_back((uint8_t)(((uint64_t)r.offsetBegin >> (i * 8)) & 0xFF));
    for (int i = 0; i < 8; i++)
        buf.push_back((uint8_t)(((uint64_t)r.offsetEnd   >> (i * 8)) & 0xFF));
    buf.push_back((uint8_t)r.type);
    return Sha256(buf.data(), buf.size());
}

static AvRecord MakeRecord(const std::vector<uint8_t>& sig,
                            int64_t ob, int64_t oe, AvObjectType type)
{
    AvRecord r;
    r.prefix = 0;
    for (int i = 0; i < 8 && i < (int)sig.size(); i++)
        r.prefix |= ((uint64_t)sig[i] << (i * 8));
    r.sigLen      = (uint32_t)sig.size();
    r.sigHash     = Sha256(sig.data(), sig.size());
    r.offsetBegin = ob;
    r.offsetEnd   = oe;
    r.type        = type;
    r.sigBytes    = sig;
    r.recordSig   = ComputeRecordSig(r);
    return r;
}

// --- Aho-Corasick automaton (optional requirement 4) ---

struct AcNode {
    int next[256];
    int fail;
    std::vector<size_t> output;
};

static std::vector<AcNode> g_ac;

static void AcBuild()
{
    g_ac.clear();
    AcNode root;
    memset(root.next, -1, sizeof(root.next));
    root.fail = 0;
    g_ac.push_back(root);

    for (size_t ri = 0; ri < g_allRecords.size(); ri++) {
        int cur = 0;
        for (uint8_t b : g_allRecords[ri].sigBytes) {
            if (g_ac[cur].next[b] == -1) {
                AcNode nd;
                memset(nd.next, -1, sizeof(nd.next));
                nd.fail = 0;
                g_ac[cur].next[b] = (int)g_ac.size();
                g_ac.push_back(nd);
            }
            cur = g_ac[cur].next[b];
        }
        g_ac[cur].output.push_back(ri);
    }

    std::queue<int> q;
    for (int c = 0; c < 256; c++) {
        if (g_ac[0].next[c] == -1)
            g_ac[0].next[c] = 0;
        else {
            g_ac[g_ac[0].next[c]].fail = 0;
            q.push(g_ac[0].next[c]);
        }
    }
    while (!q.empty()) {
        int u = q.front(); q.pop();
        for (int c = 0; c < 256; c++) {
            int v = g_ac[u].next[c];
            if (v == -1) {
                g_ac[u].next[c] = g_ac[g_ac[u].fail].next[c];
            } else {
                g_ac[v].fail = g_ac[g_ac[u].fail].next[c];
                for (size_t idx : g_ac[g_ac[v].fail].output)
                    g_ac[v].output.push_back(idx);
                q.push(v);
            }
        }
    }
}

static void InstallRecords(const std::vector<AvRecord>& records,
                           const std::wstring& date)
{
    std::lock_guard<std::mutex> lk(g_dbMtx);
    g_db.clear();
    g_allRecords.clear();
    for (const auto& r : records) {
        g_db[r.prefix].push_back(r);
        g_allRecords.push_back(r);
    }
    g_dbDate  = date;
    g_dbCount = (uint32_t)g_allRecords.size();
    AcBuild();
    RBPOLog("InstallRecords: %u records installed, AC states=%zu",
            g_dbCount, g_ac.size());
}

static bool IsNetworkAvailable()
{
    std::wstring host; int port;
    GetBackend(host, port);
    auto resp = HttpsRequest(host, port, L"GET", L"/api/health", "", "");
    return !resp.transportError;
}

static std::thread        g_schedThread;
static HANDLE             g_schedWake     = nullptr;
static std::atomic<bool>  g_schedStop{false};
static void SchedulerWorker();

void AvLoadFromBackend(const std::string& accessToken);
static void AvFetchByIds(const std::string& token, const std::vector<std::string>& ids);

void AvLoad()
{
    std::wstring dir     = AvDbGetDir();
    std::wstring dbPath  = dir + L"avdb.bin";
    std::wstring mftPath = dir + L"avdb.manifest";
    std::wstring bakDb   = dir + L"avdb.bin.bak";
    std::wstring bakMft  = dir + L"avdb.manifest.bak";
    std::wstring defDb   = dir + L"avdb.default.bin";
    std::wstring defMft  = dir + L"avdb.default.manifest";

    AvDbEnsureDefault(defDb, defMft);

    bool loaded = false;

    if (AvManifestVerify(dbPath, mftPath)) {
        std::vector<AvRecord> records;
        std::wstring date;
        size_t skipped = 0;
        std::vector<std::string> skippedIds;
        if (AvDbLoadFromFile(dbPath, records, date, &skipped, &skippedIds) && !records.empty()) {
            RBPOLog("AvLoad: main DB OK (%zu records, %zu skipped)", records.size(), skipped);
            InstallRecords(records, date);
            loaded = true;
            if (!skippedIds.empty()) {
                std::string token = StateGetAccessToken();
                if (!token.empty() && IsNetworkAvailable()) {
                    RBPOLog("AvLoad: re-fetching %zu records by id", skippedIds.size());
                    AvFetchByIds(token, skippedIds);
                }
            } else if (skipped > 0) {
                std::string token = StateGetAccessToken();
                if (!token.empty() && IsNetworkAvailable()) {
                    RBPOLog("AvLoad: %zu bad-sig records without ids — full re-fetch", skipped);
                    AvLoadFromBackend(token);
                }
            }
        }
    } else {
        RBPOLog("AvLoad: main manifest invalid");
        std::string token = StateGetAccessToken();
        if (!token.empty() && IsNetworkAvailable()) {
            RBPOLog("AvLoad: network available — forcing DB update");
            AvLoadFromBackend(token);
            loaded = !g_allRecords.empty();
        }
    }

    if (!loaded) {
        if (AvManifestVerify(bakDb, bakMft)) {
            std::vector<AvRecord> records;
            std::wstring date;
            if (AvDbLoadFromFile(bakDb, records, date) && !records.empty()) {
                RBPOLog("AvLoad: restored from backup (%zu records)", records.size());
                CopyFileW(bakDb.c_str(),  dbPath.c_str(),  FALSE);
                CopyFileW(bakMft.c_str(), mftPath.c_str(), FALSE);
                InstallRecords(records, date);
                loaded = true;
            }
        }
    }

    if (!loaded) {
        RBPOLog("AvLoad: loading default DB");
        std::vector<AvRecord> records;
        std::wstring date;
        if (AvDbLoadFromFile(defDb, records, date)) {
            InstallRecords(records, date);
        } else {
            RBPOLog("AvLoad: default DB unreadable — using hardcoded fallback");
            AvRecord rec1 = MakeRecord(
                {'R','B','P','O','T','E','S','T','V','R','S','1','.','0','0','0'},
                -1, -1, AvObjectType::PE);
            AvRecord rec2 = MakeRecord(
                {'#','R','B','P','O','T','E','S','T','V','R','S','2','.','0','0'},
                -1, -1, AvObjectType::Script);
            InstallRecords({rec1, rec2}, L"2026-05-13");
        }
    }

    RBPOLog("AvLoad: %u records active, AC states=%zu", g_dbCount, g_ac.size());

    if (!g_schedThread.joinable()) {
        g_schedStop = false;
        g_schedWake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        g_schedThread = std::thread(SchedulerWorker);
    }
}

AvDbInfo AvGetInfo()
{
    std::lock_guard<std::mutex> lk(g_dbMtx);
    AvDbInfo info;
    info.date  = g_dbDate;
    info.count = g_dbCount;
    return info;
}

static std::vector<uint8_t> HexDecode(const std::string& hex)
{
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto hc = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
            if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
            return 0;
        };
        out.push_back((uint8_t)((hc(hex[i]) << 4) | hc(hex[i + 1])));
    }
    return out;
}

static std::vector<std::string> SplitJsonObjects(const std::string& json)
{
    std::vector<std::string> objs;
    for (size_t i = 0; i < json.size(); i++) {
        if (json[i] != '{') continue;
        int depth = 0;
        size_t start = i;
        for (; i < json.size(); i++) {
            if (json[i] == '{') depth++;
            else if (json[i] == '}') { if (--depth == 0) { i++; break; } }
        }
        objs.push_back(json.substr(start, i - start));
    }
    return objs;
}

static AvRecord ParseSignatureObject(const std::string& obj)
{
    AvRecord r;
    std::string firstHex = JsonExtractString(obj, "firstBytesHex");
    std::string remHex   = JsonExtractString(obj, "remainderHashHex");
    std::string fileType = JsonExtractString(obj, "fileType");
    std::string threat   = JsonExtractString(obj, "threatName");
    std::string sigB64   = JsonExtractString(obj, "digitalSignatureBase64");
    long long   remLen   = JsonExtractNumber(obj, "remainderLength");
    long long   offStart = JsonExtractNumber(obj, "offsetStart");
    long long   offEnd   = JsonExtractNumber(obj, "offsetEnd");

    std::vector<uint8_t> firstBytes = HexDecode(firstHex);
    r.prefix = 0;
    for (int i = 0; i < 8 && i < (int)firstBytes.size(); i++)
        r.prefix |= ((uint64_t)firstBytes[i] << (i * 8));
    r.id               = JsonExtractString(obj, "id");
    r.sigLen           = (uint32_t)(firstBytes.size() + (size_t)remLen);
    r.sigBytes         = firstBytes;
    r.sigHash          = remHex.empty() ? std::vector<uint8_t>{} : HexDecode(remHex);
    r.hasRemainderHash = (remLen > 0 && !remHex.empty());
    r.offsetBegin      = offStart;
    r.offsetEnd        = offEnd;
    r.type             = (fileType == "PE") ? AvObjectType::PE : AvObjectType::Script;
    r.threatName       = Utf8ToWide(threat);
    r.rsaSig           = AvBase64Decode(sigB64);

    if (!r.rsaSig.empty() && !AvRsaVerifyRecord(r, r.rsaSig)) {
        RBPOLog("ParseSignatureObject: RSA sig invalid for id=%s threat=%s",
                r.id.c_str(), threat.c_str());
        r.rsaSig.clear();
        r.id.clear();
    }
    return r;
}

static void SaveCurrentDb()
{
    std::wstring dir     = AvDbGetDir();
    std::wstring dbPath  = dir + L"avdb.bin";
    std::wstring mftPath = dir + L"avdb.manifest";
    std::wstring bakDb   = dir + L"avdb.bin.bak";
    std::wstring bakMft  = dir + L"avdb.manifest.bak";

    std::vector<AvRecord> records;
    std::wstring date;
    {
        std::lock_guard<std::mutex> lk(g_dbMtx);
        records = g_allRecords;
        date    = g_dbDate;
    }

    if (!records.empty())
        AvDbSaveToFile(bakDb, bakMft, records, date);

    if (!AvDbSaveToFile(dbPath, mftPath, records, date)) {
        RBPOLog("SaveCurrentDb: write failed — rollback from backup");
        std::vector<AvRecord> bak; std::wstring bakDate;
        if (AvDbLoadFromFile(bakDb, bak, bakDate) && !bak.empty())
            InstallRecords(bak, bakDate);
    }
}

static void AvFetchByIds(const std::string& token,
                          const std::vector<std::string>& ids)
{
    std::string body = "{\"ids\":[";
    for (size_t i = 0; i < ids.size(); i++) {
        if (i > 0) body += ",";
        body += "\"" + ids[i] + "\"";
    }
    body += "]}";

    std::wstring host; int port;
    GetBackend(host, port);
    auto resp = HttpsRequest(host, port, L"POST", L"/api/signatures/by-ids", body, token);
    if (resp.transportError || resp.status / 100 != 2) {
        RBPOLog("AvFetchByIds: HTTP %d", resp.status);
        return;
    }

    auto objs = SplitJsonObjects(resp.body);
    if (objs.empty()) return;

    std::vector<AvRecord> merged;
    std::wstring curDate;
    {
        std::lock_guard<std::mutex> lk(g_dbMtx);
        merged  = g_allRecords;
        curDate = g_dbDate;
    }

    for (const auto& obj : objs) {
        if (JsonExtractString(obj, "status") != "ACTUAL") continue;
        std::string firstHex = JsonExtractString(obj, "firstBytesHex");
        if (firstHex.size() < 16) continue;
        AvRecord r = ParseSignatureObject(obj);
        if (r.sigBytes.size() < 8) continue;

        bool replaced = false;
        for (auto& existing : merged) {
            if (!existing.id.empty() && existing.id == r.id) {
                existing = std::move(r);
                replaced = true;
                break;
            }
        }
        if (!replaced) merged.push_back(std::move(r));
    }

    SYSTEMTIME st; GetSystemTime(&st);
    wchar_t dateBuf[32];
    swprintf_s(dateBuf, L"%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);

    InstallRecords(merged, std::wstring(dateBuf));
    SaveCurrentDb();
    RBPOLog("AvFetchByIds: merged %zu ids, total=%u", ids.size(), g_dbCount);
}

void AvLoadFromBackend(const std::string& accessToken)
{
    std::wstring host; int port;
    GetBackend(host, port);
    auto resp = HttpsRequest(host, port, L"GET", L"/api/signatures", "", accessToken);
    if (resp.transportError || resp.status / 100 != 2) {
        RBPOLog("AvLoadFromBackend: HTTP %d", resp.status);
        return;
    }

    auto objs = SplitJsonObjects(resp.body);
    std::vector<AvRecord> newRecords;
    for (const auto& obj : objs) {
        if (JsonExtractString(obj, "status") != "ACTUAL") continue;
        std::string firstHex = JsonExtractString(obj, "firstBytesHex");
        if (firstHex.size() < 16) continue;

        AvRecord r = ParseSignatureObject(obj);
        if (r.sigBytes.size() < 8) continue;
        newRecords.push_back(std::move(r));
    }

    if (newRecords.empty()) {
        RBPOLog("AvLoadFromBackend: no ACTUAL records from backend");
        return;
    }

    SYSTEMTIME st; GetSystemTime(&st);
    wchar_t dateBuf[32];
    swprintf_s(dateBuf, L"%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);

    InstallRecords(newRecords, std::wstring(dateBuf));
    SaveCurrentDb();
    RBPOLog("AvLoadFromBackend: %u records saved to disk", g_dbCount);
}

// --- Scanning via Aho-Corasick ---

static bool ScanStream(const std::vector<uint8_t>& data,
                       AvObjectType fileType,
                       std::wstring& threatName)
{
    if (g_ac.size() <= 1) return false;

    int state = 0;
    for (size_t i = 0; i < data.size(); i++) {
        state = g_ac[state].next[data[i]];
        for (size_t patIdx : g_ac[state].output) {
            const AvRecord& rec = g_allRecords[patIdx];
            if (rec.type != fileType) continue;
            int64_t matchPos = (int64_t)(i + 1 - rec.sigBytes.size());
            if (rec.offsetBegin >= 0 && matchPos < rec.offsetBegin) continue;
            if (rec.offsetEnd   >= 0 && matchPos > rec.offsetEnd)   continue;
            if (rec.hasRemainderHash) {
                size_t remLen   = rec.sigLen - (uint32_t)rec.sigBytes.size();
                size_t remStart = (size_t)matchPos + rec.sigBytes.size();
                if (remStart + remLen > data.size()) continue;
                auto h = Sha256(data.data() + remStart, remLen);
                if (h != rec.sigHash) continue;
            }
            threatName = rec.threatName.empty()
                ? std::wstring(L"RBPO.") + (rec.type == AvObjectType::PE ? L"PE.Virus" : L"Script.Virus")
                : rec.threatName;
            return true;
        }
    }
    return false;
}

static AvObjectType DetectFileType(const std::wstring& path,
                                    const std::vector<uint8_t>& head)
{
    size_t dot = path.rfind(L'.');
    if (dot != std::wstring::npos) {
        std::wstring ext = path.substr(dot);
        for (auto& c : ext) c = towlower(c);
        if (ext == L".py" || ext == L".ps1" || ext == L".js" || ext == L".vbs")
            return AvObjectType::Script;
    }
    if (head.size() >= 2 && head[0] == 'M' && head[1] == 'Z')
        return AvObjectType::PE;
    return AvObjectType::Script;
}

bool AvScanFile(const std::wstring& path, std::wstring& threatName)
{
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz = {};
    GetFileSizeEx(hFile, &sz);
    if (sz.QuadPart > 256LL * 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }

    std::vector<uint8_t> data((size_t)sz.QuadPart);
    DWORD rd = 0;
    ReadFile(hFile, data.data(), (DWORD)data.size(), &rd, nullptr);
    CloseHandle(hFile);
    data.resize(rd);

    AvObjectType type = DetectFileType(path, data);

    std::lock_guard<std::mutex> lk(g_dbMtx);
    return ScanStream(data, type, threatName);
}

std::wstring AvScanDirectory(const std::wstring& dirPath)
{
    std::wstring results;
    std::wstring search = dirPath;
    if (!search.empty() && search.back() != L'\\')
        search += L'\\';
    search += L'*';

    WIN32_FIND_DATAW fd = {};
    HANDLE hFind = FindFirstFileW(search.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return results;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
            continue;
        std::wstring full = dirPath;
        if (!full.empty() && full.back() != L'\\') full += L'\\';
        full += fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            results += AvScanDirectory(full);
        } else {
            std::wstring threat;
            if (AvScanFile(full, threat))
                results += full + L": " + threat + L"\n";
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return results;
}

// --- Optional 1: scan all fixed drives ---

std::wstring AvScanAllDrives()
{
    wchar_t buf[512] = {};
    GetLogicalDriveStringsW((DWORD)(sizeof(buf) / sizeof(wchar_t)), buf);
    std::wstring results;
    for (wchar_t* p = buf; *p; p += wcslen(p) + 1) {
        if (GetDriveTypeW(p) != DRIVE_FIXED) continue;
        std::wstring root(p);
        if (!root.empty() && root.back() == L'\\')
            root.pop_back();
        RBPOLog("AvScanAllDrives: scanning %ls", root.c_str());
        results += AvScanDirectory(root);
    }
    return results.empty() ? L"No threats detected" : results;
}

// --- Optional 2: scheduled scanning ---

static std::mutex         g_schedMtx;
static std::wstring       g_schedPath;
static long               g_schedInterval = 0;
static std::wstring       g_schedResults;
static int64_t            g_schedLastRun  = 0;

static void SchedulerWorker()
{
    while (!g_schedStop) {
        WaitForSingleObject(g_schedWake, 5000);
        if (g_schedStop) break;

        std::wstring path; long interval; int64_t lastRun;
        {
            std::lock_guard<std::mutex> lk(g_schedMtx);
            path = g_schedPath; interval = g_schedInterval; lastRun = g_schedLastRun;
        }
        if (path.empty() || interval <= 0) continue;

        int64_t now = (int64_t)time(nullptr);
        if (now - lastRun < interval) continue;

        std::wstring res = AvScanDirectory(path);
        if (res.empty()) res = L"No threats detected";

        {
            std::lock_guard<std::mutex> lk(g_schedMtx);
            g_schedResults = res;
            g_schedLastRun = (int64_t)time(nullptr);
        }
        RBPOLog("SchedulerWorker: scan complete for %ls", path.c_str());
    }
}

void AvSetSchedule(const std::wstring& path, long intervalSeconds)
{
    {
        std::lock_guard<std::mutex> lk(g_schedMtx);
        g_schedPath     = path;
        g_schedInterval = intervalSeconds;
        g_schedLastRun  = 0;
    }
    if (g_schedWake) SetEvent(g_schedWake);
    RBPOLog("AvSetSchedule: path=%ls interval=%ld", path.c_str(), intervalSeconds);
}

void AvClearSchedule()
{
    std::lock_guard<std::mutex> lk(g_schedMtx);
    g_schedPath.clear();
    g_schedInterval = 0;
    g_schedResults.clear();
    g_schedLastRun = 0;
}

std::wstring AvGetScheduleResults(int64_t& lastScanTimeUnix)
{
    std::lock_guard<std::mutex> lk(g_schedMtx);
    lastScanTimeUnix = g_schedLastRun;
    return g_schedResults.empty() ? L"No scan results yet" : g_schedResults;
}

// --- Optional 3: directory monitoring ---

struct MonitorEntry {
    std::wstring path;
    HANDLE       hDir  = INVALID_HANDLE_VALUE;
    HANDLE       hStop = nullptr;
    std::thread  thr;
};

static std::mutex                 g_monMtx;
static std::vector<MonitorEntry*> g_monitors;
static std::wstring               g_monResults;

static void MonitorWorker(MonitorEntry* e)
{
    const DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME |
                         FILE_NOTIFY_CHANGE_LAST_WRITE |
                         FILE_NOTIFY_CHANGE_SIZE;
    BYTE buf[8192];
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    while (true) {
        ResetEvent(ov.hEvent);
        if (!ReadDirectoryChangesW(e->hDir, buf, sizeof(buf), TRUE,
                                   filter, nullptr, &ov, nullptr))
            break;

        HANDLE h[2] = { e->hStop, ov.hEvent };
        DWORD w = WaitForMultipleObjects(2, h, FALSE, INFINITE);

        if (w != WAIT_OBJECT_0 + 1) {
            CancelIoEx(e->hDir, &ov);
            WaitForSingleObject(ov.hEvent, 5000);
            break;
        }

        DWORD bytes = 0;
        if (!GetOverlappedResult(e->hDir, &ov, &bytes, FALSE) || !bytes)
            continue;

        auto* fni = (FILE_NOTIFY_INFORMATION*)buf;
        do {
            if (fni->Action == FILE_ACTION_ADDED ||
                fni->Action == FILE_ACTION_MODIFIED ||
                fni->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                std::wstring name(fni->FileName, fni->FileNameLength / sizeof(wchar_t));
                std::wstring full = e->path;
                if (!full.empty() && full.back() != L'\\') full += L'\\';
                full += name;
                std::wstring threat;
                if (AvScanFile(full, threat)) {
                    std::lock_guard<std::mutex> lk(g_monMtx);
                    g_monResults += full + L": " + threat + L"\n";
                }
            }
            if (!fni->NextEntryOffset) break;
            fni = (FILE_NOTIFY_INFORMATION*)((BYTE*)fni + fni->NextEntryOffset);
        } while (true);
    }

    CloseHandle(ov.hEvent);
}

void AvAddMonitorDirectory(const std::wstring& path)
{
    HANDLE hDir = CreateFileW(path.c_str(), FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (hDir == INVALID_HANDLE_VALUE) {
        RBPOLog("AvAddMonitorDirectory: cannot open '%ls' err=%lu",
                path.c_str(), GetLastError());
        return;
    }
    auto* e  = new MonitorEntry();
    e->path  = path;
    e->hDir  = hDir;
    e->hStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    e->thr   = std::thread(MonitorWorker, e);
    {
        std::lock_guard<std::mutex> lk(g_monMtx);
        g_monitors.push_back(e);
    }
    RBPOLog("AvAddMonitorDirectory: monitoring '%ls'", path.c_str());
}

void AvRemoveMonitorDirectory(const std::wstring& path)
{
    MonitorEntry* toStop = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_monMtx);
        for (auto it = g_monitors.begin(); it != g_monitors.end(); ++it) {
            if (_wcsicmp((*it)->path.c_str(), path.c_str()) == 0) {
                toStop = *it;
                g_monitors.erase(it);
                break;
            }
        }
    }
    if (!toStop) return;
    RBPOLog("AvRemoveMonitorDirectory: stopping '%ls'", toStop->path.c_str());
    SetEvent(toStop->hStop);
    CancelIoEx(toStop->hDir, nullptr);
    if (toStop->thr.joinable()) toStop->thr.join();
    CloseHandle(toStop->hDir);
    CloseHandle(toStop->hStop);
    delete toStop;
}

std::wstring AvGetMonitorResults()
{
    std::lock_guard<std::mutex> lk(g_monMtx);
    return g_monResults.empty() ? L"No threats detected" : g_monResults;
}

static std::thread        g_updateThread;
static HANDLE             g_updateWake     = nullptr;
static std::atomic<bool>  g_updateStop{false};
static long               g_updateInterval = 0;

static void UpdateWorker()
{
    int64_t lastUpdate = 0;
    while (!g_updateStop) {
        WaitForSingleObject(g_updateWake, 10000);
        if (g_updateStop) break;
        if (g_updateInterval <= 0) continue;

        int64_t now = (int64_t)time(nullptr);
        if (now - lastUpdate < g_updateInterval) continue;
        lastUpdate = now;

        std::string token = StateGetAccessToken();
        if (token.empty()) continue;

        RBPOLog("UpdateWorker: starting periodic DB update");
        AvLoadFromBackend(token);
    }
}

void AvDbStartUpdate(long intervalSeconds)
{
    g_updateInterval = intervalSeconds;
    if (!g_updateThread.joinable()) {
        g_updateStop = false;
        g_updateWake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        g_updateThread = std::thread(UpdateWorker);
    }
    RBPOLog("AvDbStartUpdate: interval=%ld s", intervalSeconds);
}

void AvDbStopUpdate()
{
    g_updateStop = true;
    if (g_updateWake) SetEvent(g_updateWake);
    if (g_updateThread.joinable()) g_updateThread.join();
    if (g_updateWake) { CloseHandle(g_updateWake); g_updateWake = nullptr; }
    RBPOLog("AvDbStopUpdate: done");
}

void AvShutdown()
{
    AvDbStopUpdate();

    g_schedStop = true;
    if (g_schedWake) SetEvent(g_schedWake);
    if (g_schedThread.joinable()) g_schedThread.join();
    if (g_schedWake) { CloseHandle(g_schedWake); g_schedWake = nullptr; }

    std::lock_guard<std::mutex> lk(g_monMtx);
    for (auto* e : g_monitors) {
        SetEvent(e->hStop);
        CancelIoEx(e->hDir, nullptr);
        if (e->thr.joinable()) e->thr.join();
        CloseHandle(e->hDir);
        CloseHandle(e->hStop);
        delete e;
    }
    g_monitors.clear();
}

} // namespace rbpo
