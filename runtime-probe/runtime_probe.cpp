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
static constexpr uintptr_t kPersistentMin = 0xF0000000u;
static const char* kDesertHills = "_c4/Levels/Level_0500_DesertHills/Level_0500_DesertHills";
static const char* kBuffaloGap  = "_c4/Levels/Level_2300_BuffaloGap/Level_2300_BuffaloGap";

static FILE* gLog = nullptr;
static std::mutex gLogMutex;
static std::vector<uintptr_t> gCandidates;
static volatile bool gRunning = true;

static void Log(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(gLogMutex);
    if (!gLog) return;
    SYSTEMTIME st{}; GetLocalTime(&st);
    std::fprintf(gLog, "[%02u:%02u:%02u.%03u] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args; va_start(args, fmt); std::vfprintf(gLog, fmt, args); va_end(args);
    std::fputc('\n', gLog); std::fflush(gLog);
}

static bool IsReadable(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static bool IsWritable(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static std::string SafeCString(uintptr_t addr, size_t maxLen=260)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!addr || !VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || !IsReadable(mbi.Protect)) return "<unreadable>";
    size_t avail = (uintptr_t)mbi.BaseAddress + mbi.RegionSize - addr;
    size_t want = std::min(maxLen, avail);
    std::vector<char> b(want);
    SIZE_T got=0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, b.data(), want, &got) || !got) return "<unreadable>";
    size_t n=0; while (n<got && b[n]) ++n;
    if (n==got) return "<unterminated>";
    return std::string(b.data(), n);
}

static std::vector<uintptr_t> FindPersistent()
{
    std::vector<uintptr_t> hits;
    const size_t needleLen = std::strlen(kDesertHills);
    constexpr size_t kChunk = 1u << 20;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t p = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end = (uintptr_t)si.lpMaximumApplicationAddress;

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))) break;
        uintptr_t base = (uintptr_t)mbi.BaseAddress;
        size_t size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && IsWritable(mbi.Protect) && size > needleLen) {
            std::vector<unsigned char> buf(kChunk + needleLen + 1);
            for (size_t off=0; off<size;) {
                size_t toRead = std::min(kChunk + needleLen, size-off);
                SIZE_T got=0;
                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(base+off), buf.data(), toRead, &got) && got > needleLen) {
                    size_t primary = std::min(kChunk, (size_t)got);
                    for (size_t i=0; i<primary && i+needleLen<got; ++i) {
                        if (buf[i] == (unsigned char)kDesertHills[0] && std::memcmp(buf.data()+i, kDesertHills, needleLen)==0 && buf[i+needleLen]==0) {
                            uintptr_t a = base+off+i;
                            if (a >= kPersistentMin) hits.push_back(a);
                            i += needleLen;
                        }
                    }
                }
                if (size-off <= kChunk) break;
                off += kChunk;
            }
        }
        if (base+size <= p) break;
        p = base+size;
    }
    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
    return hits;
}

static bool StillSource(uintptr_t a)
{
    size_t n = std::strlen(kDesertHills)+1;
    std::vector<char> b(n); SIZE_T got=0;
    return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)a, b.data(), n, &got) && got==n && std::memcmp(b.data(), kDesertHills, n)==0;
}

static void Scan()
{
    gCandidates = FindPersistent();
    Log("---- PERSISTENT DESERT HILLS CANDIDATES: %zu ----", gCandidates.size());
    for (size_t i=0;i<gCandidates.size();++i) Log("  candidate[%zu] = 0x%08X", i, (unsigned)gCandidates[i]);
    if (gCandidates.size() != 12) {
        Log("WARNING: expected 12 persistent candidates on a clean frontend visit; restart before interpreting this test");
        MessageBeep(MB_ICONHAND);
    } else {
        Log("SCAN COMPLETE: 12 candidates cached");
        MessageBeep(MB_ICONASTERISK);
    }
}

static void PatchRange(size_t begin, size_t finish, const char* label)
{
    if (gCandidates.empty()) Scan();
    if (gCandidates.size() < finish) {
        Log("PATCH ABORTED: %s needs indices [%zu,%zu), only %zu candidate(s) available", label, begin, finish, gCandidates.size());
        MessageBeep(MB_ICONHAND);
        return;
    }

    Log("---- PATCH %s: indices [%zu,%zu) of %zu ----", label, begin, finish, gCandidates.size());
    const size_t oldLen=std::strlen(kDesertHills), newLen=std::strlen(kBuffaloGap);
    std::vector<char> repl(oldLen+1,0); std::memcpy(repl.data(), kBuffaloGap, newLen);
    unsigned patched=0;
    for (size_t i=begin;i<finish;++i) {
        uintptr_t a=gCandidates[i];
        if (!StillSource(a)) { Log("  candidate[%zu] stale/skipped 0x%08X", i, (unsigned)a); continue; }
        SIZE_T w=0;
        if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)a, repl.data(), repl.size(), &w) && w==repl.size()) {
            ++patched;
            Log("  patched candidate[%zu] 0x%08X", i, (unsigned)a);
        } else {
            Log("  FAILED candidate[%zu] 0x%08X err=%lu", i, (unsigned)a, GetLastError());
        }
    }
    Log("PATCH COMPLETE: %s patched=%u", label, patched);
    Log("IMPORTANT: success means the later LEVEL CHANGE says BuffaloGap. A crash while LEVEL CHANGE remains DesertHills only means this candidate is sensitive.");
    MessageBeep(patched ? MB_ICONASTERISK : MB_ICONHAND);
}

static DWORD WINAPI Thread(LPVOID)
{
    char exe[MAX_PATH]{}; GetModuleFileNameA(nullptr, exe, MAX_PATH);
    Log("NFSTR ITC Runtime Probe v6 - candidates 3/4/5 isolation");
    Log("EXE: %s", exe);
    Log("Use a FRESH GAME LAUNCH for every test.");
    Log("Hotkeys: F6=scan+beep; F7=C3; F8=C4; F9=C5; F10=C1(recheck)");
    bool p6=false,p7=false,p8=false,p9=false,p10=false;
    std::string last;
    while (gRunning) {
        std::string now=SafeCString(kGameCurrentLevel);
        if (now!=last && now!="<unreadable>") { Log("LEVEL CHANGE: %s", now.c_str()); last=now; }

        bool f6=(GetAsyncKeyState(VK_F6)&0x8000)!=0;
        bool f7=(GetAsyncKeyState(VK_F7)&0x8000)!=0;
        bool f8=(GetAsyncKeyState(VK_F8)&0x8000)!=0;
        bool f9=(GetAsyncKeyState(VK_F9)&0x8000)!=0;
        bool f10=(GetAsyncKeyState(VK_F10)&0x8000)!=0;

        if (f6&&!p6) Scan();
        if (f7&&!p7) PatchRange(3,4,"CANDIDATE 3");
        if (f8&&!p8) PatchRange(4,5,"CANDIDATE 4");
        if (f9&&!p9) PatchRange(5,6,"CANDIDATE 5");
        if (f10&&!p10) PatchRange(1,2,"CANDIDATE 1 RECHECK");

        p6=f6;p7=f7;p8=f8;p9=f9;p10=f10;
        Sleep(100);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE m,DWORD r,LPVOID)
{
    if (r==DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(m);
        fopen_s(&gLog,"NFSTR_ITC_RuntimeProbe.log","w");
        HANDLE h=CreateThread(nullptr,0,Thread,nullptr,0,nullptr); if(h) CloseHandle(h);
    } else if (r==DLL_PROCESS_DETACH) gRunning=false;
    return TRUE;
}
