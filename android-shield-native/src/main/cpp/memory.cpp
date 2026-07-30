#include "memory.h"

#include <fstream>
#include <sstream>
#include <string>

namespace androidshield::memory {

int self_check() {
    std::ifstream in("/proc/self/maps");
    if (!in) {
        return 0;
    }
    int flags = 0;
    std::string line;
    while (std::getline(in, line)) {
        // Look for writable+executable mappings (rwxp) — often shellcode / JIT hooks.
        if (line.find("rwxp") != std::string::npos) {
            flags |= FLAG_RWX;
        }
        if (line.find("frida") != std::string::npos ||
            line.find("gadget") != std::string::npos ||
            line.find("libsubstrate") != std::string::npos) {
            flags |= FLAG_SUSPICIOUS_NAME;
        }
    }
    return flags;
}

}  // namespace androidshield::memory
