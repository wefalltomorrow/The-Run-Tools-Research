#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>

static constexpr uintptr_t kGameCurrentLevel   = 0x0289BDC8;
static constexpr uintptr_t kGameSecondaryLevel = 0x0289BCC8;
static constexpr uintptr_t kLevelObjectGlobal  = 0x02888F80;

static const char* kDesertHills = "_c4/Levels/Level_0500_DesertHills/Level_0500_DesertHills";
static const char* kBuffaloGap  = "_c4/Levels/Level_2300_BuffaloGap/Level_2300_BuffaloGap";

static FILE* gLog = nullptr;
static std::mutex gLogMutex;
static std::mutex gHitsMutex;
static std::vector<uintptr_t> gLastHits;
static std::vector<uintptr_t> gPatched;
static volatile bool gRunning = true;

static void Log(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(gLogMutex);
    if (!gLog) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::fprintf(gLog, "[%02u:%02u:%02u.%03u] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, fmt);
    std::vfprintf(gLog, fmt, args);
    va_end(args);
    std::fputc('\n', gLog);
    std::fflush(gLog);
}

static bool IsReadableProtect(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static bool IsWritableProtect(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static bool ReadSelf(uintptr_t address, void* out, size_t size)
{
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), out, size, &got) && got == size;
}

static std::string SafeCString(uintptr_t address, size_t maxLen = 260)
{
    if (!address) return "<null>";
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) ||
        mbi.State != MEM_COMMIT || !IsReadableProtect(mbi.Protect)) return "<unreadable>";

    const uintptr_t end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    const size_t want = std::min(maxLen, static_cast<size_t>(end - address));
    if (!want) return "<unreadable>";
    std::vector<char> buf(want);
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), buf.data(), want, &got) || !got)
        return "<unreadable>";
    size_t n = 0;
    while (n < got && buf[n]) ++n;
    if (n == got) return "<unterminated/unreadable>";
    return std::string(buf.data(), n);
}

static void DumpState()
{
    Log("---- STATE DUMP ----");
    Log("global current  [0x%08X] = %s", (unsigned)kGameCurrentLevel, SafeCString(kGameCurrentLevel).c_str());
    Log("global secondary[0x%08X] = %s", (unsigned)kGameSecondaryLevel, SafeCString(kGameSecondaryLevel).c_str());
    uintptr_t obj = 0;
    if (!ReadSelf(kLevelObjectGlobal, &obj, sizeof(obj))) {
        Log("level object global read failed");
        return;
    }
    Log("level object global [0x%08X] -> 0x%08X", (unsigned)kLevelObjectGlobal, (unsigned)obj);
    if (obj) {
        uintptr_t p = 0;
        if (ReadSelf(obj + 0x9C, &p, sizeof(p)))
            Log("level object +0x9C -> 0x%08X = %s", (unsigned)p, SafeCString(p).c_str());
    }
}

static std::vector<uintptr_t> FindWritableCString(const char* needle)
{
    std::vector<uintptr_t> hits;
    const size_t needleLen = std::strlen(needle);
    constexpr size_t kChunk = 1u << 20;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t p = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t end = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi))) break;
        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const size_t size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && IsWritableProtect(mbi.Protect) && size > needleLen) {
            std::vector<unsigned char> buf(kChunk + needleLen + 1);
            for (size_t off = 0; off < size;) {
                const size_t toRead = std::min(kChunk + needleLen, size - off);
                SIZE_T got = 0;
                if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(base + off), buf.data(), toRead, &got) && got > needleLen) {
                    const size_t primary = std::min(kChunk, static_cast<size_t>(got));
                    for (size_t i = 0; i < primary && i + needleLen < got; ++i) {
                        if (buf[i] == static_cast<unsigned char>(needle[0]) &&
                            std::memcmp(buf.data() + i, needle, needleLen) == 0 && buf[i + needleLen] == 0) {
                            hits.push_back(base + off + i);
                            i += needleLen;
                        }
                    }
                }
                if (size - off <= kChunk) break;
                off += kChunk;
            }
        }
        if (base + size <= p) break;
        p = base + size;
    }
    std::sort(hits.begin(), hits.end());
    return hits;
}

static void CacheHits(const std::vector<uintptr_t>& hits)
{
    std::lock_guard<std::mutex> lock(gHitsMutex);
    gLastHits = hits;
}

static std::vector<uintptr_t> GetHits()
{
    std::lock_guard<std::mutex> lock(gHitsMutex);
    return gLastHits;
}

static void ScanAndCache()
{
    auto hits = FindWritableCString(kDesertHills);
    CacheHits(hits);
    Log("---- DESERT HILLS CANDIDATES: %zu ----", hits.size());
    for (size_t i = 0; i < hits.size(); ++i)
        Log("  candidate[%zu] = 0x%08X", i, (unsigned)hits[i]);
}

static bool StillDesertHills(uintptr_t addr)
{
    const size_t n = std::strlen(kDesertHills) + 1;
    std::vector<char> buf(n);
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr), buf.data(), n, &got) &&
           got == n && std::memcmp(buf.data(), kDesertHills, n) == 0;
}

static void RestorePatched()
{
    const size_t n = std::strlen(kDesertHills) + 1;
    Log("---- RESTORE: %zu patched candidate(s) ----", gPatched.size());
    for (uintptr_t addr : gPatched) {
        SIZE_T written = 0;
        if (WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(addr), kDesertHills, n, &written) && written == n)
            Log("  restored 0x%08X", (unsigned)addr);
        else
            Log("  restore FAILED 0x%08X err=%lu", (unsigned)addr, GetLastError());
    }
    gPatched.clear();
    CacheHits({});
}

static void PatchRange(bool upperHalf)
{
    auto hits = GetHits();
    if (hits.empty()) {
        Log("No cached candidates; scanning now...");
        hits = FindWritableCString(kDesertHills);
        CacheHits(hits);
    }
    if (hits.empty()) {
        Log("PATCH ABORTED: no Desert Hills candidates found");
        MessageBeep(MB_ICONHAND);
        return;
    }

    const size_t mid = hits.size() / 2;
    const size_t begin = upperHalf ? mid : 0;
    const size_t finish = upperHalf ? hits.size() : mid;
    Log("---- BINARY PATCH %s: indices [%zu,%zu) of %zu ----",
        upperHalf ? "UPPER" : "LOWER", begin, finish, hits.size());

    const size_t oldLen = std::strlen(kDesertHills);
    const size_t newLen = std::strlen(kBuffaloGap);
    std::vector<char> replacement(oldLen + 1, 0);
    std::memcpy(replacement.data(), kBuffaloGap, newLen);

    unsigned patched = 0;
    for (size_t i = begin; i < finish; ++i) {
        const uintptr_t addr = hits[i];
        if (!StillDesertHills(addr)) {
            Log("  candidate[%zu] stale/skipped 0x%08X", i, (unsigned)addr);
            continue;
        }
        SIZE_T written = 0;
        if (WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(addr), replacement.data(), replacement.size(), &written) && written == replacement.size()) {
            gPatched.push_back(addr);
            ++patched;
            Log("  patched candidate[%zu] 0x%08X", i, (unsigned)addr);
        } else {
            Log("  FAILED candidate[%zu] 0x%08X err=%lu", i, (unsigned)addr, GetLastError());
        }
    }
    Log("BINARY PATCH COMPLETE: half=%s patched=%u", upperHalf ? "UPPER" : "LOWER", patched);
    MessageBeep(patched ? MB_ICONASTERISK : MB_ICONHAND);
}

static DWORD WINAPI ProbeThread(LPVOID)
{
    char exePath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    Log("NFSTR ITC Runtime Probe v3 - binary candidate isolation");
    Log("EXE: %s", exePath);
    Log("Hotkeys: F6=scan/cache candidates, F8=patch LOWER half, F9=patch UPPER half, F10=restore all");
    DumpState();

    bool p6=false,p8=false,p9=false,p10=false;
    std::string lastLevel;
    while (gRunning) {
        std::string now = SafeCString(kGameCurrentLevel);
        if (now != lastLevel && now != "<unreadable>") {
            Log("LEVEL CHANGE: %s", now.c_str());
            lastLevel = now;
        }
        bool f6  = (GetAsyncKeyState(VK_F6)  & 0x8000) != 0;
        bool f8  = (GetAsyncKeyState(VK_F8)  & 0x8000) != 0;
        bool f9  = (GetAsyncKeyState(VK_F9)  & 0x8000) != 0;
        bool f10 = (GetAsyncKeyState(VK_F10) & 0x8000) != 0;
        if (f6 && !p6)  { DumpState(); ScanAndCache(); }
        if (f8 && !p8)  { DumpState(); PatchRange(false); }
        if (f9 && !p9)  { DumpState(); PatchRange(true); }
        if (f10 && !p10){ RestorePatched(); DumpState(); }
        p6=f6; p8=f8; p9=f9; p10=f10;
        Sleep(100);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        fopen_s(&gLog, "NFSTR_ITC_RuntimeProbe.log", "w");
        HANDLE h = CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    } else if (reason == DLL_PROCESS_DETACH) {
        gRunning = false;
    }
    return TRUE;
}
