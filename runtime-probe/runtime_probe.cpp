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

static constexpr uintptr_t kGameCurrentLevel = 0x0289BDC8;

static const char* kSLEIdentity = "_c4/Gameplay/ChallengeSeries/SLE/SLE_1";
static const char* kVanillaName = "ID_CS_SLE_1_NAME";
static const char* kVanillaLevel = "_c4/Levels/Level_0500_DesertHills/Level_0500_DesertHills";
static const char* kVanillaFilter = "ID_CARFILTER_TIER4_SLE_1";
static const char* kVanillaDebug = "CSLE_1";
static const char* kVanillaDesc = "ID_CS_SLE_1_DESC";
static const char* kHybridName = "ID_CS_SCA_1_NAME";
static const char* kHybridLevel = "_c4/Levels/Level_2300_BuffaloGap/Level_2300_BuffaloGap";
static const char* kHybridFilter = "ID_CARFILTER_TIER4_SCA_1";
static const char* kHybridDebug = "CSCA_1";
static const char* kHybridDesc = "ID_CS_SCA_1_DESC";

static FILE* gLog = nullptr;
static std::mutex gLogMutex;
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

static bool IsReadable(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static std::string SafeCString(uintptr_t addr, size_t maxLen = 260)
{
    if (!addr) return "<null>";
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || !IsReadable(mbi.Protect))
        return "<unreadable>";
    uintptr_t end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    size_t want = std::min(maxLen, (size_t)(end - addr));
    std::vector<char> b(want);
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, b.data(), want, &got) || !got)
        return "<unreadable>";
    size_t n = 0;
    while (n < got && b[n]) ++n;
    if (n == got) return "<unterminated>";
    return std::string(b.data(), n);
}

static std::vector<uintptr_t> FindExactCString(const char* needle)
{
    std::vector<uintptr_t> hits;
    const size_t n = std::strlen(needle);
    constexpr size_t kChunk = 1u << 20;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t p = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t end = (uintptr_t)si.lpMaximumApplicationAddress;

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))) break;
        uintptr_t base = (uintptr_t)mbi.BaseAddress;
        size_t size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && IsReadable(mbi.Protect) && size > n) {
            std::vector<unsigned char> buf(kChunk + n + 1);
            for (size_t off = 0; off < size;) {
                size_t toRead = std::min(kChunk + n, size - off);
                SIZE_T got = 0;
                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(base + off), buf.data(), toRead, &got) && got > n) {
                    size_t primary = std::min(kChunk, (size_t)got);
                    for (size_t i = 0; i < primary && i + n < got; ++i) {
                        if (buf[i] == (unsigned char)needle[0] &&
                            std::memcmp(buf.data() + i, needle, n) == 0 &&
                            buf[i + n] == 0) {
                            hits.push_back(base + off + i);
                            i += n;
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
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
    return hits;
}

static bool ReadWindow(uintptr_t anchor, size_t before, size_t after,
                       uintptr_t& startOut, std::vector<unsigned char>& out)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)anchor, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || !IsReadable(mbi.Protect))
        return false;
    uintptr_t regionStart = (uintptr_t)mbi.BaseAddress;
    uintptr_t regionEnd = regionStart + mbi.RegionSize;
    uintptr_t start = anchor > before ? anchor - before : anchor;
    if (start < regionStart) start = regionStart;
    uintptr_t finish = std::min(regionEnd, anchor + after);
    if (finish <= start) return false;
    out.resize((size_t)(finish - start));
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)start, out.data(), out.size(), &got) || !got)
        return false;
    out.resize((size_t)got);
    startOut = start;
    return true;
}

static std::vector<size_t> FindInBuffer(const std::vector<unsigned char>& b, const char* needle)
{
    std::vector<size_t> r;
    size_t n = std::strlen(needle);
    if (!n || b.size() < n) return r;
    for (size_t i = 0; i + n <= b.size(); ++i) {
        if (b[i] == (unsigned char)needle[0] && std::memcmp(b.data() + i, needle, n) == 0) {
            r.push_back(i);
            i += n - 1;
        }
    }
    return r;
}

static bool Has(const std::vector<unsigned char>& b, const char* needle)
{
    return !FindInBuffer(b, needle).empty();
}

static void Report(const char* label, const char* needle, uintptr_t anchor,
                   uintptr_t start, const std::vector<unsigned char>& b)
{
    auto hits = FindInBuffer(b, needle);
    Log("    %-15s : %zu hit(s)", label, hits.size());
    for (size_t off : hits) {
        uintptr_t at = start + off;
        Log("      0x%08X delta=%lld  %s", (unsigned)at,
            (long long)at - (long long)anchor, needle);
    }
}

static void TraceHybridPresence()
{
    Log("============================================================");
    Log("===== READ-ONLY TEST 9 HYBRID PRESENCE TRACE =====");
    Log("No game memory will be modified.");

    auto identities = FindExactCString(kSLEIdentity);
    Log("SLE_1 identity copies: %zu", identities.size());

    unsigned vanillaCount = 0;
    unsigned hybridCount = 0;
    unsigned otherCount = 0;

    for (size_t i = 0; i < identities.size(); ++i) {
        uintptr_t anchor = identities[i];
        Log("------------------------------------------------------------");
        Log("SLE identity copy[%zu] = 0x%08X", i, (unsigned)anchor);

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery((LPCVOID)anchor, &mbi, sizeof(mbi))) {
            Log("    regionBase=0x%08X allocBase=0x%08X size=0x%zX type=0x%lX protect=0x%lX",
                (unsigned)(uintptr_t)mbi.BaseAddress,
                (unsigned)(uintptr_t)mbi.AllocationBase,
                mbi.RegionSize,
                (unsigned long)mbi.Type,
                (unsigned long)mbi.Protect);
        }

        uintptr_t start = 0;
        std::vector<unsigned char> b;
        if (!ReadWindow(anchor, 0x500, 0x500, start, b)) {
            Log("    FAILED to read neighborhood");
            ++otherCount;
            continue;
        }

        bool vanilla = Has(b, kVanillaName) && Has(b, kVanillaLevel) &&
                       Has(b, kVanillaFilter) && Has(b, kVanillaDebug) && Has(b, kVanillaDesc);
        bool hybrid = Has(b, kHybridName) && Has(b, kHybridLevel) &&
                      Has(b, kHybridFilter) && Has(b, kHybridDebug) && Has(b, kHybridDesc);

        if (hybrid && !vanilla) {
            ++hybridCount;
            Log("    CLASSIFICATION: *** TEST 9 HYBRID SLE_1 FOUND ***");
        } else if (vanilla && !hybrid) {
            ++vanillaCount;
            Log("    CLASSIFICATION: VANILLA SLE_1");
        } else if (hybrid && vanilla) {
            ++hybridCount;
            ++vanillaCount;
            Log("    CLASSIFICATION: MIXED WINDOW (vanilla + hybrid fingerprints)");
        } else {
            ++otherCount;
            Log("    CLASSIFICATION: OTHER / INCOMPLETE SLE_1 COPY");
        }

        Report("SLE identity", kSLEIdentity, anchor, start, b);
        Report("vanilla name", kVanillaName, anchor, start, b);
        Report("vanilla level", kVanillaLevel, anchor, start, b);
        Report("vanilla filter", kVanillaFilter, anchor, start, b);
        Report("vanilla debug", kVanillaDebug, anchor, start, b);
        Report("vanilla desc", kVanillaDesc, anchor, start, b);
        Report("hybrid name", kHybridName, anchor, start, b);
        Report("hybrid level", kHybridLevel, anchor, start, b);
        Report("hybrid filter", kHybridFilter, anchor, start, b);
        Report("hybrid debug", kHybridDebug, anchor, start, b);
        Report("hybrid desc", kHybridDesc, anchor, start, b);
    }

    Log("------------------------------------------------------------");
    Log("GLOBAL SCA FINGERPRINT COUNTS (real Carbon SCA_1 also creates these):");
    const char* globals[] = {kHybridName, kHybridLevel, kHybridFilter, kHybridDebug, kHybridDesc};
    for (const char* s : globals)
        Log("    '%s' => %zu hit(s)", s, FindExactCString(s).size());

    Log("SUMMARY: vanilla identity windows=%u, Test9 hybrid identity windows=%u, other/incomplete=%u",
        vanillaCount, hybridCount, otherCount);

    if (hybridCount) {
        Log("CONCLUSION SIGNAL: Test 9 hybrid IS present in RAM under the SLE_1 identity.");
        MessageBeep(MB_ICONASTERISK);
    } else {
        Log("CONCLUSION SIGNAL: NO Test 9 hybrid SLE_1 identity block found in RAM.");
        Log("At this frontend point, Frostbite has not loaded the modified Test 9 SLE_1 payload.");
        MessageBeep(MB_ICONHAND);
    }
    Log("===== HYBRID PRESENCE TRACE COMPLETE =====");
}

static DWORD WINAPI ProbeThread(LPVOID)
{
    char exe[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    Log("============================================================");
    Log("===== NEW GAME SESSION | PID %lu =====", GetCurrentProcessId());
    Log("NFSTR ITC Runtime Probe v9 - Test 9 hybrid presence tracer");
    Log("EXE: %s", exe);
    Log("Log mode: APPEND");
    Log("READ-ONLY BUILD: no WriteProcessMemory calls are used.");
    Log("Hotkey: F6=classify every SLE_1 identity copy; beep when finished");

    bool prevF6 = false;
    std::string lastLevel;
    while (gRunning) {
        std::string now = SafeCString(kGameCurrentLevel);
        if (now != lastLevel && now != "<unreadable>") {
            Log("LEVEL CHANGE: %s", now.c_str());
            lastLevel = now;
        }
        bool f6 = (GetAsyncKeyState(VK_F6) & 0x8000) != 0;
        if (f6 && !prevF6) TraceHybridPresence();
        prevF6 = f6;
        Sleep(100);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        fopen_s(&gLog, "NFSTR_ITC_RuntimeProbe.log", "a");
        HANDLE h = CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    } else if (reason == DLL_PROCESS_DETACH) {
        gRunning = false;
        if (gLog) {
            std::fflush(gLog);
            std::fclose(gLog);
            gLog = nullptr;
        }
    }
    return TRUE;
}
