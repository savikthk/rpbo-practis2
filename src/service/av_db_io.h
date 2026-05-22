#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

namespace rbpo {

struct AvRecord;

std::wstring AvDbGetDir();
std::wstring AvDbMakePath(const wchar_t* filename);

std::vector<uint8_t> AvBase64Decode(const std::string& b64);
std::string          AvHexEncode(const std::vector<uint8_t>& data);
bool                 AvRsaVerifyRecord(const AvRecord& r, const std::vector<uint8_t>& rsaSig);

std::vector<uint8_t> AvDbSerialize(const std::vector<AvRecord>& records,
                                    const std::wstring& date);

bool AvDbDeserialize(const std::vector<uint8_t>& data,
                     std::vector<AvRecord>& outRecords,
                     std::wstring& outDate,
                     size_t* outSkipped = nullptr,
                     std::vector<std::string>* outSkippedIds = nullptr);

bool AvDbSaveToFile(const std::wstring& dbPath,
                    const std::wstring& mftPath,
                    const std::vector<AvRecord>& records,
                    const std::wstring& date);

bool AvManifestVerify(const std::wstring& dbPath,
                      const std::wstring& mftPath);

bool AvDbLoadFromFile(const std::wstring& dbPath,
                      std::vector<AvRecord>& outRecords,
                      std::wstring& outDate,
                      size_t* outSkipped = nullptr,
                      std::vector<std::string>* outSkippedIds = nullptr);

void AvDbEnsureDefault(const std::wstring& dbPath,
                       const std::wstring& mftPath);

} // namespace rbpo
