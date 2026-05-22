#pragma once
#include <string>

namespace rbpo {

/* Extract first occurrence of `"key": "..."` (string value). Returns "" if absent. */
std::string JsonExtractString(const std::string& json, const std::string& key);

/* Extract first occurrence of `"key": <number>`. Returns 0 if absent. */
long long JsonExtractNumber(const std::string& json, const std::string& key);

/* Extract first occurrence of `"key": true|false`. */
bool JsonExtractBool(const std::string& json, const std::string& key, bool defv = false);

/* Escape string for inline JSON. */
std::string JsonEscape(const std::string& s);

/* Convert wide → UTF-8. */
std::string WideToUtf8(const std::wstring& w);
std::wstring Utf8ToWide(const std::string& s);

} // namespace rbpo
