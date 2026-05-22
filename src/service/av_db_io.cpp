#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <cstring>
#include <cstdio>
#include "av_db_io.h"
#include "av_engine.h"
#include "json_util.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace rbpo {

extern "C" void RBPOLog(const char* fmt, ...);

static const uint8_t g_hmacKey[32] = {
    0x4B,0x9F,0x3A,0x7E, 0x21,0xC5,0x8D,0xF2,
    0x6A,0x1B,0xE4,0x90, 0x37,0xD8,0x5C,0x02,
    0x74,0xAF,0xB3,0x69, 0x4E,0x12,0x88,0xF7,
    0x3C,0x51,0x9A,0x6D, 0x25,0xE0,0xB6,0x43,
};

static const uint8_t g_rsaPubKeyDer[294] = {
    0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,
    0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0f,0x00,
    0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00,0xc6,0x8c,0x4a,
    0xd0,0x64,0x6e,0xb5,0xc2,0x9b,0x5c,0x24,0x9d,0xd4,0x4b,0xfa,
    0x12,0x53,0x8e,0x60,0x44,0xc5,0xdf,0x65,0x94,0xee,0x15,0xdc,
    0xd8,0xa0,0x37,0x50,0x75,0xd9,0x11,0x81,0xbe,0x0a,0xc7,0x21,
    0xfa,0xa1,0x7a,0xdc,0x63,0xaf,0xfa,0x2e,0x3e,0xef,0x57,0xaf,
    0x50,0x36,0x55,0xfa,0x3a,0x60,0xa5,0x78,0x3f,0x27,0x0d,0x6f,
    0xa4,0xba,0xe0,0x0e,0x9e,0x5d,0xfe,0xf6,0x8e,0x0a,0x1b,0x68,
    0x5e,0xc0,0xf1,0xe5,0x8e,0xc7,0x9b,0x96,0x66,0x12,0x5c,0x3a,
    0x6f,0xd9,0x0f,0x93,0x1e,0x09,0x27,0x34,0xb7,0x02,0x56,0xdc,
    0xe5,0x98,0x53,0x12,0x9a,0x28,0x40,0x4d,0x99,0xe6,0xec,0x77,
    0x4c,0x06,0xc4,0x6b,0x97,0xc2,0xe2,0x5b,0x9b,0xd2,0x9d,0x52,
    0x3a,0x2e,0x66,0x25,0x55,0x25,0x56,0x74,0x32,0xa4,0xdb,0x86,
    0xcd,0xe4,0x77,0x7a,0xac,0xd5,0x9a,0xc1,0xaf,0x24,0x5a,0x07,
    0xef,0x83,0x18,0x59,0x39,0xff,0xa4,0x8d,0xa3,0xc8,0x70,0x02,
    0x69,0x53,0x82,0x75,0xe2,0x7b,0x1c,0xac,0x12,0x82,0x46,0x8b,
    0x1f,0xae,0xe5,0xea,0x62,0xc8,0xd8,0xe8,0x4e,0xbb,0xfe,0x61,
    0xc7,0xea,0xfb,0xfc,0xba,0x7b,0xa6,0xfe,0x78,0x47,0xa2,0xea,
    0xa5,0x10,0xdf,0x33,0x42,0x4c,0x99,0x3f,0xcf,0x03,0xff,0x23,
    0x27,0xd8,0xa8,0x60,0xb5,0x40,0x35,0x0d,0xc9,0x27,0x83,0xf5,
    0x7e,0x32,0xb4,0xb5,0x7d,0xfa,0xa0,0x3f,0xef,0xa1,0x44,0x1b,
    0xdf,0x5f,0xa5,0xf9,0xe7,0x21,0x3e,0x82,0xbe,0x4a,0x5f,0x56,
    0x90,0xc4,0x3a,0x08,0xdf,0xa3,0x53,0x6b,0xbe,0x60,0x98,0x4f,
    0xdd,0x02,0x03,0x01,0x00,0x01
};

static const char DB_MAGIC[4]  = {'R','B','D','B'};
static const char MFT_MAGIC[4] = {'R','B','M','F'};
static const uint16_t DB_VERSION   = 2;
static const uint16_t DB_VERSION_1 = 1;

static void WLE16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(x & 0xFF);
    v.push_back((x >> 8) & 0xFF);
}
static void WLE32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; i++) v.push_back((x >> (i * 8)) & 0xFF);
}
static void WLE64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((x >> (i * 8)) & 0xFF);
}
static void WBytes(std::vector<uint8_t>& v, const void* p, size_t n) {
    const auto* b = static_cast<const uint8_t*>(p);
    v.insert(v.end(), b, b + n);
}

static bool RLE16(const uint8_t* p, size_t sz, size_t& off, uint16_t& out) {
    if (off + 2 > sz) return false;
    out = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8);
    off += 2;
    return true;
}
static bool RLE32(const uint8_t* p, size_t sz, size_t& off, uint32_t& out) {
    if (off + 4 > sz) return false;
    out = 0;
    for (int i = 0; i < 4; i++) out |= ((uint32_t)p[off + i] << (i * 8));
    off += 4;
    return true;
}
static bool RLE64(const uint8_t* p, size_t sz, size_t& off, uint64_t& out) {
    if (off + 8 > sz) return false;
    out = 0;
    for (int i = 0; i < 8; i++) out |= ((uint64_t)p[off + i] << (i * 8));
    off += 8;
    return true;
}
static bool RByte(const uint8_t* p, size_t sz, size_t& off, uint8_t& out) {
    if (off >= sz) return false;
    out = p[off++];
    return true;
}
static bool RBytes(const uint8_t* p, size_t sz, size_t& off,
                   size_t n, std::vector<uint8_t>& out) {
    if (off + n > sz) return false;
    out.assign(p + off, p + off + n);
    off += n;
    return true;
}

static std::vector<uint8_t> Sha256Buf(const void* data, size_t len) {
    std::vector<uint8_t> result(32, 0);
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return result;
    DWORD objSz = 0, copied = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      (PUCHAR)&objSz, sizeof(DWORD), &copied, 0);
    std::vector<uint8_t> obj(objSz);
    if (BCryptCreateHash(hAlg, &hHash, obj.data(), objSz, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }
    BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    BCryptFinishHash(hHash, result.data(), 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

static std::vector<uint8_t> HmacSha256Buf(const uint8_t* key, size_t keyLen,
                                            const void* data, size_t dataLen) {
    std::vector<uint8_t> result(32, 0);
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0)
        return result;
    DWORD objSz = 0, copied = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      (PUCHAR)&objSz, sizeof(DWORD), &copied, 0);
    std::vector<uint8_t> obj(objSz);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptCreateHash(hAlg, &hHash, obj.data(), objSz,
                         const_cast<PUCHAR>(key), (ULONG)keyLen, 0) < 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }
    BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0);
    BCryptFinishHash(hHash, result.data(), 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

static std::vector<uint8_t> Sha256File(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::vector<uint8_t> result(32, 0);

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        CloseHandle(hFile); return result;
    }
    DWORD objSz = 0, copied = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      (PUCHAR)&objSz, sizeof(DWORD), &copied, 0);
    std::vector<uint8_t> obj(objSz);
    BCryptCreateHash(hAlg, &hHash, obj.data(), objSz, nullptr, 0, 0);

    uint8_t buf[65536];
    DWORD rd;
    while (ReadFile(hFile, buf, sizeof(buf), &rd, nullptr) && rd > 0)
        BCryptHashData(hHash, buf, rd, 0);

    BCryptFinishHash(hHash, result.data(), 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return result;
}

static std::vector<uint8_t> ComputeRecordSig(const AvRecord& r) {
    std::vector<uint8_t> buf;
    buf.reserve(8 + 4 + r.sigHash.size() + 8 + 8 + 1);
    for (int i = 0; i < 8; i++)
        buf.push_back((uint8_t)((r.prefix >> (i * 8)) & 0xFF));
    for (int i = 0; i < 4; i++)
        buf.push_back((uint8_t)((r.sigLen >> (i * 8)) & 0xFF));
    buf.insert(buf.end(), r.sigHash.begin(), r.sigHash.end());
    for (int i = 0; i < 8; i++)
        buf.push_back((uint8_t)(((uint64_t)(int64_t)r.offsetBegin >> (i * 8)) & 0xFF));
    for (int i = 0; i < 8; i++)
        buf.push_back((uint8_t)(((uint64_t)(int64_t)r.offsetEnd   >> (i * 8)) & 0xFF));
    buf.push_back((uint8_t)r.type);
    return Sha256Buf(buf.data(), buf.size());
}

static std::vector<uint8_t> ReadFileBytes(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER sz = {};
    GetFileSizeEx(hFile, &sz);
    if (sz.QuadPart > 64LL * 1024 * 1024) { CloseHandle(hFile); return {}; }
    std::vector<uint8_t> data((size_t)sz.QuadPart);
    DWORD rd = 0;
    ReadFile(hFile, data.data(), (DWORD)data.size(), &rd, nullptr);
    CloseHandle(hFile);
    data.resize(rd);
    return data;
}

static bool WriteFileBytes(const std::wstring& path,
                           const std::vector<uint8_t>& data) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    WriteFile(hFile, data.data(), (DWORD)data.size(), &wr, nullptr);
    CloseHandle(hFile);
    return wr == (DWORD)data.size();
}

std::vector<uint8_t> AvBase64Decode(const std::string& b64) {
    if (b64.empty()) return {};
    DWORD outLen = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                               CRYPT_STRING_BASE64, nullptr, &outLen, nullptr, nullptr))
        return {};
    std::vector<uint8_t> out(outLen);
    CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(),
                          CRYPT_STRING_BASE64, out.data(), &outLen, nullptr, nullptr);
    out.resize(outLen);
    return out;
}

std::string AvHexEncode(const std::vector<uint8_t>& data) {
    static const char HEX[] = "0123456789abcdef";
    std::string s;
    s.reserve(data.size() * 2);
    for (uint8_t b : data) {
        s += HEX[b >> 4];
        s += HEX[b & 0xF];
    }
    return s;
}

static std::string CanonicEsc(const std::string& s) {
    std::string r = "\"";
    for (unsigned char c : s) {
        if      (c == '"')  r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c == '\b') r += "\\b";
        else if (c == '\t') r += "\\t";
        else if (c == '\n') r += "\\n";
        else if (c == '\f') r += "\\f";
        else if (c == '\r') r += "\\r";
        else if (c < 0x20) {
            char buf[8]; sprintf_s(buf, "\\u%04x", c);
            r += buf;
        } else r += (char)c;
    }
    r += "\"";
    return r;
}

static std::string BuildCanonicalJson(const std::string& fileType,
                                       const std::string& firstBytesHex,
                                       long long offsetEnd,
                                       long long offsetStart,
                                       const std::string& remainderHashHex,
                                       long long remainderLength,
                                       const std::string& threatName) {
    char obuf[32], osbuf[32], rlbuf[32];
    sprintf_s(obuf,  "%lld", offsetEnd);
    sprintf_s(osbuf, "%lld", offsetStart);
    sprintf_s(rlbuf, "%lld", remainderLength);

    std::string j = "{";
    j += CanonicEsc("fileType") + ":" + CanonicEsc(fileType) + ",";
    j += CanonicEsc("firstBytesHex") + ":" + CanonicEsc(firstBytesHex) + ",";
    j += CanonicEsc("offsetEnd") + ":" + obuf + ",";
    j += CanonicEsc("offsetStart") + ":" + osbuf + ",";
    j += CanonicEsc("remainderHashHex") + ":" + CanonicEsc(remainderHashHex) + ",";
    j += CanonicEsc("remainderLength") + ":" + rlbuf + ",";
    j += CanonicEsc("status") + ":" + CanonicEsc("ACTUAL") + ",";
    j += CanonicEsc("threatName") + ":" + CanonicEsc(threatName);
    j += "}";
    return j;
}

bool AvRsaVerifyRecord(const AvRecord& r, const std::vector<uint8_t>& rsaSig) {
    if (rsaSig.empty()) return false;

    std::string fileType    = (r.type == AvObjectType::PE) ? "PE" : "Script";
    std::string firstHex    = AvHexEncode(r.sigBytes);
    std::string remHashHex  = AvHexEncode(r.sigHash);
    long long   remLen      = (long long)r.sigLen - (long long)r.sigBytes.size();
    std::string threatUtf8  = WideToUtf8(r.threatName);

    std::string canonical = BuildCanonicalJson(
        fileType, firstHex,
        r.offsetEnd, r.offsetBegin,
        remHashHex, remLen, threatUtf8);

    auto hash = Sha256Buf(canonical.data(), canonical.size());

    CERT_PUBLIC_KEY_INFO* spki = nullptr;
    DWORD spkiSize = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                              X509_PUBLIC_KEY_INFO,
                              g_rsaPubKeyDer, (DWORD)sizeof(g_rsaPubKeyDer),
                              CRYPT_DECODE_ALLOC_FLAG, nullptr,
                              &spki, &spkiSize))
        return false;

    BCRYPT_KEY_HANDLE hKey = nullptr;
    BOOL ok = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, spki, 0, nullptr, &hKey);
    LocalFree(spki);
    if (!ok || !hKey) return false;

    BCRYPT_PKCS1_PADDING_INFO pi = {};
    pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    NTSTATUS st = BCryptVerifySignature(
        hKey, &pi,
        hash.data(), (ULONG)hash.size(),
        const_cast<PUCHAR>(rsaSig.data()), (ULONG)rsaSig.size(),
        BCRYPT_PAD_PKCS1);

    BCryptDestroyKey(hKey);
    return st == 0;
}

std::wstring AvDbGetDir() {
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring p(exePath);
    auto pos = p.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? p.substr(0, pos + 1) : L".\\";
}

std::wstring AvDbMakePath(const wchar_t* filename) {
    return AvDbGetDir() + filename;
}

std::vector<uint8_t> AvDbSerialize(const std::vector<AvRecord>& records,
                                    const std::wstring& date) {
    std::vector<uint8_t> recBuf;
    for (const auto& r : records) {
        WLE64(recBuf, r.prefix);
        WLE32(recBuf, r.sigLen);
        auto hashLen = (uint8_t)r.sigHash.size();
        recBuf.push_back(hashLen);
        WBytes(recBuf, r.sigHash.data(), hashLen);
        WLE64(recBuf, (uint64_t)(int64_t)r.offsetBegin);
        WLE64(recBuf, (uint64_t)(int64_t)r.offsetEnd);
        recBuf.push_back((uint8_t)r.type);
        recBuf.push_back(r.hasRemainderHash ? 1 : 0);
        WLE32(recBuf, (uint32_t)r.sigBytes.size());
        WBytes(recBuf, r.sigBytes.data(), r.sigBytes.size());
        std::string threatUtf8 = WideToUtf8(r.threatName);
        WLE16(recBuf, (uint16_t)threatUtf8.size());
        WBytes(recBuf, threatUtf8.data(), threatUtf8.size());
        auto sig = ComputeRecordSig(r);
        WBytes(recBuf, sig.data(), 32);
        WLE16(recBuf, (uint16_t)r.id.size());
        WBytes(recBuf, r.id.data(), r.id.size());
        WLE16(recBuf, (uint16_t)r.rsaSig.size());
        WBytes(recBuf, r.rsaSig.data(), r.rsaSig.size());
    }

    auto dataHash = Sha256Buf(recBuf.data(), recBuf.size());

    std::vector<uint8_t> out;
    WBytes(out, DB_MAGIC, 4);
    WLE16(out, DB_VERSION);
    WLE32(out, (uint32_t)records.size());
    std::string dateUtf8 = WideToUtf8(date);
    WLE16(out, (uint16_t)dateUtf8.size());
    WBytes(out, dateUtf8.data(), dateUtf8.size());
    WBytes(out, dataHash.data(), 32);
    out.insert(out.end(), recBuf.begin(), recBuf.end());
    return out;
}

bool AvDbDeserialize(const std::vector<uint8_t>& data,
                     std::vector<AvRecord>& outRecords,
                     std::wstring& outDate,
                     size_t* outSkipped,
                     std::vector<std::string>* outSkippedIds) {
    const uint8_t* p  = data.data();
    size_t         sz = data.size();
    size_t         off = 0;

    if (sz < 4 || memcmp(p, DB_MAGIC, 4) != 0) {
        RBPOLog("AvDbDeserialize: bad magic");
        return false;
    }
    off = 4;

    uint16_t version;
    if (!RLE16(p, sz, off, version) ||
        (version != DB_VERSION && version != DB_VERSION_1)) {
        RBPOLog("AvDbDeserialize: unsupported version %u", version);
        return false;
    }
    bool v2 = (version == DB_VERSION);

    uint32_t count;
    if (!RLE32(p, sz, off, count)) return false;

    uint16_t dateLen;
    if (!RLE16(p, sz, off, dateLen)) return false;
    if (off + dateLen > sz) return false;
    std::string dateUtf8(reinterpret_cast<const char*>(p + off), dateLen);
    off += dateLen;
    outDate = Utf8ToWide(dateUtf8);

    if (off + 32 > sz) return false;
    std::vector<uint8_t> storedHash(p + off, p + off + 32);
    off += 32;

    auto computedHash = Sha256Buf(p + off, sz - off);
    if (computedHash != storedHash) {
        RBPOLog("AvDbDeserialize: DataHash mismatch — file corrupted");
        return false;
    }

    outRecords.clear();
    outRecords.reserve(count);
    size_t skipped = 0;

    for (uint32_t i = 0; i < count; i++) {
        AvRecord r;

        uint64_t pfx;
        if (!RLE64(p, sz, off, pfx)) {
            RBPOLog("AvDbDeserialize: truncated at record %u", i);
            break;
        }
        r.prefix = pfx;

        uint32_t sigLen;
        if (!RLE32(p, sz, off, sigLen)) break;
        r.sigLen = sigLen;

        uint8_t hashLen;
        if (!RByte(p, sz, off, hashLen)) break;
        if (hashLen > 0) {
            if (!RBytes(p, sz, off, hashLen, r.sigHash)) break;
        }

        uint64_t obRaw, oeRaw;
        if (!RLE64(p, sz, off, obRaw)) break;
        if (!RLE64(p, sz, off, oeRaw)) break;
        r.offsetBegin = (int64_t)obRaw;
        r.offsetEnd   = (int64_t)oeRaw;

        uint8_t type, hasRem;
        if (!RByte(p, sz, off, type))   break;
        if (!RByte(p, sz, off, hasRem)) break;
        r.type             = (AvObjectType)type;
        r.hasRemainderHash = (hasRem != 0);

        uint32_t sbLen;
        if (!RLE32(p, sz, off, sbLen)) break;
        if (sbLen > 0) {
            if (!RBytes(p, sz, off, sbLen, r.sigBytes)) break;
        }

        uint16_t threatLen;
        if (!RLE16(p, sz, off, threatLen)) break;
        if (off + threatLen > sz) break;
        std::string threatUtf8(reinterpret_cast<const char*>(p + off), threatLen);
        off += threatLen;
        r.threatName = Utf8ToWide(threatUtf8);

        std::vector<uint8_t> storedRecSig;
        if (!RBytes(p, sz, off, 32, storedRecSig)) break;

        auto expectedSig = ComputeRecordSig(r);
        if (expectedSig != storedRecSig) {
            RBPOLog("AvDbDeserialize: record %u internal sig invalid — skipped", i);
            skipped++;
            if (v2) {
                uint16_t idLen = 0; RLE16(p, sz, off, idLen);
                if (off + idLen <= sz) off += idLen;
                uint16_t rsaLen = 0; RLE16(p, sz, off, rsaLen);
                if (off + rsaLen <= sz) off += rsaLen;
            }
            continue;
        }
        r.recordSig = storedRecSig;

        if (v2) {
            uint16_t idLen;
            if (!RLE16(p, sz, off, idLen)) break;
            if (off + idLen > sz) break;
            r.id.assign(reinterpret_cast<const char*>(p + off), idLen);
            off += idLen;

            uint16_t rsaLen;
            if (!RLE16(p, sz, off, rsaLen)) break;
            if (off + rsaLen > sz) break;
            if (rsaLen > 0) {
                r.rsaSig.assign(p + off, p + off + rsaLen);
                off += rsaLen;

                if (!AvRsaVerifyRecord(r, r.rsaSig)) {
                    RBPOLog("AvDbDeserialize: record %u RSA sig invalid — skipped (id=%s)",
                            i, r.id.c_str());
                    if (outSkippedIds && !r.id.empty())
                        outSkippedIds->push_back(r.id);
                    skipped++;
                    continue;
                }
            } else {
                off += rsaLen;
            }
        }

        outRecords.push_back(std::move(r));
    }

    if (outSkipped) *outSkipped = skipped;
    RBPOLog("AvDbDeserialize: %zu records loaded, %zu skipped",
            outRecords.size(), skipped);
    return true;
}

bool AvDbSaveToFile(const std::wstring& dbPath,
                    const std::wstring& mftPath,
                    const std::vector<AvRecord>& records,
                    const std::wstring& date) {
    auto data = AvDbSerialize(records, date);
    if (!WriteFileBytes(dbPath, data)) {
        RBPOLog("AvDbSaveToFile: write '%ls' failed (err=%lu)",
                dbPath.c_str(), GetLastError());
        return false;
    }

    auto fileHash = Sha256Buf(data.data(), data.size());

    std::vector<uint8_t> mft;
    WBytes(mft, MFT_MAGIC, 4);
    WLE16(mft, DB_VERSION);
    WBytes(mft, fileHash.data(), 32);
    auto sig = HmacSha256Buf(g_hmacKey, sizeof(g_hmacKey), mft.data(), mft.size());
    WBytes(mft, sig.data(), 32);

    if (!WriteFileBytes(mftPath, mft)) {
        RBPOLog("AvDbSaveToFile: write manifest '%ls' failed (err=%lu)",
                mftPath.c_str(), GetLastError());
        return false;
    }

    RBPOLog("AvDbSaveToFile: saved %zu records to '%ls'",
            records.size(), dbPath.c_str());
    return true;
}

bool AvManifestVerify(const std::wstring& dbPath,
                      const std::wstring& mftPath) {
    auto mft = ReadFileBytes(mftPath);
    if (mft.size() < 70) {
        RBPOLog("AvManifestVerify: manifest missing or too small (%zu bytes)",
                mft.size());
        return false;
    }

    if (memcmp(mft.data(), MFT_MAGIC, 4) != 0) {
        RBPOLog("AvManifestVerify: bad manifest magic");
        return false;
    }

    size_t   off = 4;
    uint16_t ver;
    if (!RLE16(mft.data(), mft.size(), off, ver) || ver > DB_VERSION) {
        RBPOLog("AvManifestVerify: bad manifest version %u", ver);
        return false;
    }

    std::vector<uint8_t> storedFileHash;
    if (!RBytes(mft.data(), mft.size(), off, 32, storedFileHash)) return false;

    std::vector<uint8_t> storedSig;
    if (!RBytes(mft.data(), mft.size(), off, 32, storedSig)) return false;

    size_t hmacLen = 4 + 2 + 32;
    auto expectedSig = HmacSha256Buf(g_hmacKey, sizeof(g_hmacKey),
                                      mft.data(), hmacLen);
    if (expectedSig != storedSig) {
        RBPOLog("AvManifestVerify: HMAC mismatch — manifest tampered or key changed");
        return false;
    }

    auto actualFileHash = Sha256File(dbPath);
    if (actualFileHash.empty()) {
        RBPOLog("AvManifestVerify: cannot hash db file '%ls'", dbPath.c_str());
        return false;
    }
    if (actualFileHash != storedFileHash) {
        RBPOLog("AvManifestVerify: db file hash mismatch for '%ls'", dbPath.c_str());
        return false;
    }

    RBPOLog("AvManifestVerify: OK for '%ls'", dbPath.c_str());
    return true;
}

bool AvDbLoadFromFile(const std::wstring& dbPath,
                      std::vector<AvRecord>& outRecords,
                      std::wstring& outDate,
                      size_t* outSkipped,
                      std::vector<std::string>* outSkippedIds) {
    auto data = ReadFileBytes(dbPath);
    if (data.empty()) {
        RBPOLog("AvDbLoadFromFile: cannot read '%ls' (err=%lu)",
                dbPath.c_str(), GetLastError());
        return false;
    }
    return AvDbDeserialize(data, outRecords, outDate, outSkipped, outSkippedIds);
}

void AvDbEnsureDefault(const std::wstring& dbPath,
                       const std::wstring& mftPath) {
    if (AvManifestVerify(dbPath, mftPath)) {
        RBPOLog("AvDbEnsureDefault: default DB already valid");
        return;
    }

    RBPOLog("AvDbEnsureDefault: generating default DB at '%ls'", dbPath.c_str());

    auto makeRec = [](const std::vector<uint8_t>& sig,
                       AvObjectType type,
                       const std::wstring& threat) -> AvRecord {
        AvRecord r;
        r.prefix = 0;
        for (int i = 0; i < 8 && i < (int)sig.size(); i++)
            r.prefix |= ((uint64_t)sig[i] << (i * 8));
        r.sigLen           = (uint32_t)sig.size();
        r.sigBytes         = sig;
        r.hasRemainderHash = false;
        r.offsetBegin      = -1;
        r.offsetEnd        = -1;
        r.type             = type;
        r.threatName       = threat;

        std::vector<uint8_t> buf;
        for (int i = 0; i < 8; i++)
            buf.push_back((uint8_t)((r.prefix >> (i * 8)) & 0xFF));
        for (int i = 0; i < 4; i++)
            buf.push_back((uint8_t)((r.sigLen >> (i * 8)) & 0xFF));
        buf.insert(buf.end(), r.sigHash.begin(), r.sigHash.end());
        for (int i = 0; i < 8; i++)
            buf.push_back((uint8_t)(((uint64_t)(int64_t)r.offsetBegin >> (i * 8)) & 0xFF));
        for (int i = 0; i < 8; i++)
            buf.push_back((uint8_t)(((uint64_t)(int64_t)r.offsetEnd >> (i * 8)) & 0xFF));
        buf.push_back((uint8_t)r.type);
        r.recordSig = Sha256Buf(buf.data(), buf.size());
        return r;
    };

    std::vector<AvRecord> records;
    records.push_back(makeRec(
        {'R','B','P','O','T','E','S','T','V','R','S','1','.','0','0','0'},
        AvObjectType::PE, L"RBPO.PE.TestVirus.1"));
    records.push_back(makeRec(
        {'#','R','B','P','O','T','E','S','T','V','R','S','2','.','0','0'},
        AvObjectType::Script, L"RBPO.Script.TestVirus.2"));

    AvDbSaveToFile(dbPath, mftPath, records, L"2026-05-13");
}

} // namespace rbpo
