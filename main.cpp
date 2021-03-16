#include <iostream>
#include "xorstr.hpp"
#include <urlmon.h>
#include <random>
#include <Psapi.h>
#include <winternl.h>
#include <WinInet.h>
#include <fstream>
#include <string>
#include <stdlib.h>
#pragma comment(lib,"Wininet.lib")
#define MAX_PROCESSES 1024 
#pragma comment(lib, "urlmon.lib")
char spoof;
typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

void system_no_output(std::string command)
{
    command.insert(0, "/C ");

    SHELLEXECUTEINFOA ShExecInfo = { 0 };
    ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    ShExecInfo.hwnd = NULL;
    ShExecInfo.lpVerb = NULL;
    ShExecInfo.lpFile = "cmd.exe";
    ShExecInfo.lpParameters = command.c_str();
    ShExecInfo.lpDirectory = NULL;
    ShExecInfo.nShow = SW_HIDE;
    ShExecInfo.hInstApp = NULL;

    if (ShellExecuteExA(&ShExecInfo) == FALSE)

        WaitForSingleObject(ShExecInfo.hProcess, INFINITE);

    DWORD rv;
    GetExitCodeProcess(ShExecInfo.hProcess, &rv);
    CloseHandle(ShExecInfo.hProcess);
}

DWORD FindProcess(__in_z LPCTSTR lpcszFileName)
{
    LPDWORD lpdwProcessIds;
    LPTSTR  lpszBaseName;
    HANDLE  hProcess;
    DWORD   i, cdwProcesses, dwProcessId = 0;

    lpdwProcessIds = (LPDWORD)HeapAlloc(GetProcessHeap(), 0, MAX_PROCESSES * sizeof(DWORD));
    if (lpdwProcessIds != NULL)
    {
        if (EnumProcesses(lpdwProcessIds, MAX_PROCESSES * sizeof(DWORD), &cdwProcesses))
        {
            lpszBaseName = (LPTSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH * sizeof(TCHAR));
            if (lpszBaseName != NULL)
            {
                cdwProcesses /= sizeof(DWORD);
                for (i = 0; i < cdwProcesses; i++)
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lpdwProcessIds[i]);
                    if (hProcess != NULL)
                    {
                        if (GetModuleBaseName(hProcess, NULL, lpszBaseName, MAX_PATH) > 0)
                        {
                            if (!lstrcmpi(lpszBaseName, lpcszFileName))
                            {
                                dwProcessId = lpdwProcessIds[i];
                                CloseHandle(hProcess);
                                break;
                            }
                        }
                        CloseHandle(hProcess);
                    }
                }
                HeapFree(GetProcessHeap(), 0, (LPVOID)lpszBaseName);
            }
        }
        HeapFree(GetProcessHeap(), 0, (LPVOID)lpdwProcessIds);
    }
    return dwProcessId;
}

void CloseDebuggers1() {
}

void bsod()
{
    BOOLEAN bEnabled;
    ULONG uResp;
    LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
    LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtRaiseHardError");
    pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
    pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
    NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
    NtCall2(STATUS_FLOAT_MULTIPLE_FAULTS, 0, 0, 0, 6, &uResp);
}

void debuggerfound() {
    if (IsDebuggerPresent())
    {
        bsod();
    }
}


void nignog() {
    if (FindWindowA(NULL, ("The Wireshark Network Analyzer"))) { bsod(); }
    if (FindWindowA(NULL, ("Progress Telerik Fiddler Web Debugger"))) { bsod(); }
    if (FindWindowA(NULL, ("Fiddler"))) { bsod(); }
    if (FindWindowA(NULL, ("HTTP Debugger"))) { bsod(); }
    if (FindWindowA(NULL, ("x64dbg"))) { bsod(); }
    if (FindWindowA(NULL, ("dnSpy"))) { bsod(); }
    if (FindWindowA(NULL, ("FolderChangesView"))) { bsod(); }
    if (FindWindowA(NULL, ("BinaryNinja"))) { bsod(); }
    if (FindWindowA(NULL, ("HxD"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 7.2"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 7.1"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 7.0"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 6.9"))) { bsod(); }
    if (FindWindowA(NULL, ("Cheat Engine 6.8"))) { bsod(); }
    if (FindWindowA(NULL, ("Ida"))) { bsod(); }
    if (FindWindowA(NULL, ("Ida Pro"))) { bsod(); }
    if (FindWindowA(NULL, ("Ida Freeware"))) { bsod(); }
    if (FindWindowA(NULL, ("HTTP Debugger Pro"))) { bsod(); }
    if (FindWindowA(NULL, ("Process Hacker"))) { bsod(); }
    if (FindWindowA(NULL, ("Process Hacker 2"))) { bsod(); }
    if (FindWindowA(NULL, ("OllyDbg"))) { bsod(); }
}

void down()
{
    HRESULT hr = URLDownloadToFileA(NULL, XorStr("link 1").c_str(), XorStr("c:\\Windows\\apppatch\\Custom\\Custom64\\youdllname").c_str(), 0, NULL);
    HRESULT hr1 = URLDownloadToFileA(NULL, XorStr("link 2 ").c_str(), XorStr("c:\\Windows\\apppatch\\Custom\\Custom64\\you driver name").c_str(), 0, NULL);
    HRESULT hr2 = URLDownloadToFileA(NULL, XorStr("link 3 ").c_str(), XorStr("c:\\Windows\\apppatch\\Custom\\Custom64\\you inject name").c_str(), 0, NULL);
    HRESULT hr3 = URLDownloadToFileA(NULL, XorStr("link 4").c_str(), XorStr("c:\\Windows\\apppatch\\Custom\\Custom64\\youmodmapname").c_str(), 0, NULL);
    HRESULT hr4 = URLDownloadToFileA(NULL, XorStr("link 5").c_str(), XorStr("c:\\Windows\\apppatch\\Custom\\Custom64\\spoofer name").c_str(), 0, NULL);

}

bool FileExists(const std::string& filename) {
    std::ifstream ifile(filename.c_str());
    return (bool)ifile;

}

void Delete()
{

}

void Inject()
{
    

    system_no_output(XorStr("c:\\Windows\\apppatch\\Custom\\Custom64\\you inject name").c_str());
    Beep(888, 400);
    nignog();
    Delete();
    Sleep(5000);
    nignog();
    exit(0);
}

#ifdef max
#undef max
#endif

using std::cin;
using std::endl;
using std::cerr;

void scrollbar()
{
    try {
        HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;

        GetConsoleScreenBufferInfo(console, &csbi);
        COORD scrollbar = {
            csbi.srWindow.Right - csbi.srWindow.Left + 1,
            csbi.srWindow.Bottom - csbi.srWindow.Top + 1
        };

        if (console == 0) {
            throw 0;
        }
        else {
            SetConsoleScreenBufferSize(console, scrollbar);
        }
    }
    catch (...) {
        cerr << "Error removing scrollbar" << endl;
    }

}

void init()
{


    POINT OldCursorPos;
    GetCursorPos(&OldCursorPos);
    INPUT    Input = { 0 };
    ::ZeroMemory(&Input, sizeof(INPUT));
    Input.type = INPUT_MOUSE;
    Input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
    ::SendInput(1, &Input, sizeof(INPUT));
    BlockInput(true);
    SetCursorPos(0, 0);
    ::ZeroMemory(&Input, sizeof(INPUT));
    Input.type = INPUT_MOUSE;
    Input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
    ::SendInput(1, &Input, sizeof(INPUT));
    SetCursorPos(0, 0);
    SetCursorPos(OldCursorPos.x, OldCursorPos.y);
    BlockInput(false);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
    HWND handle = GetConsoleWindow();
    CONSOLE_SCREEN_BUFFER_INFO info;
    GetConsoleScreenBufferInfo(handle, &info);
    COORD new_size =
    {
        info.srWindow.Right - info.srWindow.Left + 1,
        info.srWindow.Bottom - info.srWindow.Top + 1
    };
    SetConsoleScreenBufferSize(handle, new_size);
    HWND consoleWindow = GetConsoleWindow();
    SetWindowLong(consoleWindow, GWL_STYLE, GetWindowLong(consoleWindow, GWL_STYLE) & ~WS_EX_RIGHTSCROLLBAR & ~WS_MAXIMIZEBOX & ~WS_SIZEBOX & ~WS_MINIMIZEBOX);
    HANDLE hInput;
    DWORD prev_mode;
    hInput = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hInput, &prev_mode);
    SetConsoleMode(hInput, prev_mode & ENABLE_EXTENDED_FLAGS);
    HWND consoleWindowHandle = GetConsoleWindow();
    if (consoleWindowHandle)
    {
        SetWindowPos(
            consoleWindowHandle,
            HWND_TOPMOST,
            0, 0,
            0, 0,
            SWP_DRAWFRAME | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW
        );
        ShowWindow(
            consoleWindowHandle,
            SW_NORMAL
        );
    }
}

void FindFortnite() {
    system("cls");
    init();
    scrollbar();
    HWND console = GetConsoleWindow();
    RECT ConsoleRect{};
    MoveWindow(console, ConsoleRect.left, ConsoleRect.top, 550, 600, TRUE);
    HWND Window = NULL;
    std::cout << "\n   Waiting for FortniteClient-Win64-Shipping.exe to start..." << std::endl;
    CloseDebuggers1();
    nignog();
    while (Window == NULL)
    {
        Window = FindWindowA(0, "Fortnite  ");
        Sleep(1);
    }
    CloseDebuggers1();
    nignog();
    Beep(888, 400);
    system("cls");
    std::cout << "\n   Process found!" << std::endl;
    Sleep(2000);
    CloseDebuggers1();
    nignog();
    system("cls");
    std::cout << "\n   Press F2 in the lobby to inject" << std::endl;
    CloseDebuggers1();
    nignog();
    while (true)
    {
        if (GetAsyncKeyState(VK_F2))
        {
            Inject();
            CloseDebuggers1();
            nignog();
        }
    }
    Sleep(5000);
}

std::string random_string(std::size_t length)
{

    const std::string CHARACTERS = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<> distribution(0, CHARACTERS.size() - 1);

    std::string random_string;

    for (std::size_t i = 0; i < length; ++i)
    {
        random_string += CHARACTERS[distribution(generator)];
    }

    return random_string;
}

int main()
{
    SetConsoleTitleA(XorStr("Fortnite-Cheat-Loader").c_str());
    Beep(888, 400);
    bool checkconnection = InternetCheckConnection(L"https://www.google.com/", FLAG_ICC_FORCE_CONNECTION, 0);
    CloseDebuggers1();
    nignog();
    system_no_output("taskkill /F /IM EpicGamesLauncher.exe");
    system_no_output("taskkill /F /IM EasyAntiCheatLauncher.exe");
    system_no_output("taskkill /F /IM BEService.exe");
    system_no_output("taskkill /F /IM Fortnite.exe");
    system_no_output("taskkill /F /IM BattleEyeLauncher.exe");

    CloseDebuggers1();
    nignog();

    std::string key;
    system("color B");

    std::cout << "\n   Connecting..";
    Sleep(1500);
    system("cls");

    if (!checkconnection) {
        std::cout << "\n\n   Connection Failed!";
        Sleep(1000);
        exit(1);
    }

    CloseDebuggers1();
    nignog();

    std::string name = random_string(15) + XorStr(".exe");
    SetConsoleTitleA(name.c_str());

    std::cout << "\n   Initailizing...";
    Sleep(2000);
    CloseDebuggers1();
    nignog();

    down();

    CloseDebuggers1();
    nignog();

    system_no_output(XorStr("c:\\Windows\\apppatch\\Custom\\Custom64\\drivername").c_str());

    system("cls");

    CloseDebuggers1();
    nignog();

    std::cout << "\n   Would you like to spoof? (UNSTABLE) [Y/N]";
    CloseDebuggers1();
    nignog();
    cin >> spoof;
    if ((spoof == 'y') || (spoof == 'Y')) {
        system("cls");
        std::cout << "\n   Spoofing...";

        system_no_output(XorStr("c:\\Windows\\apppatch\\Custom\\Custom64\\spoofername").c_str());

        Sleep(700);

        CloseDebuggers1();
        nignog();

        FindFortnite();

        CloseDebuggers1();
        nignog();
    }
    else
    {
        CloseDebuggers1();
        nignog();

        FindFortnite();

        CloseDebuggers1();
        nignog();
    }
}