#include "anti_hook.h"

#include <cctype>
#include <cstdio>
#include <dirent.h>
#include <fstream>
#include <string>
#include <unistd.h>

namespace androidshield::anti_hook {
namespace {

bool contains_ci(const std::string &hay, const char *needle) {
    if (hay.empty() || needle == nullptr || *needle == '\0') {
        return false;
    }
    auto lower = [](unsigned char c) { return static_cast<char>(std::tolower(c)); };
    std::string h;
    h.reserve(hay.size());
    for (char c : hay) {
        h.push_back(lower(static_cast<unsigned char>(c)));
    }
    std::string n;
    for (const char *p = needle; *p; ++p) {
        n.push_back(lower(static_cast<unsigned char>(*p)));
    }
    return h.find(n) != std::string::npos;
}

std::string read_file(const char *path) {
    std::ifstream in(path);
    if (!in) {
        return {};
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

int scan_maps() {
    const std::string maps = read_file("/proc/self/maps");
    if (maps.empty()) {
        return 0;
    }
    int flags = 0;
    static const char *frida[] = {
        "frida", "gadget", "frida-agent", "frida-gadget", "linjector",
    };
    for (const char *m : frida) {
        if (contains_ci(maps, m)) {
            flags |= FLAG_FRIDA_MAPS;
            break;
        }
    }
    static const char *xposed[] = {
        "xposed", "lsposed", "edxposed", "substrate", "libsandhook", "libyahfa", "riru", "zygisk",
    };
    for (const char *m : xposed) {
        if (contains_ci(maps, m)) {
            flags |= FLAG_XPOSED_MAPS;
            break;
        }
    }
    // Executable anonymous mappings can indicate inline hooks / shellcode.
    if (maps.find("r-xp") != std::string::npos && maps.find("[anon:") != std::string::npos) {
        // Too noisy alone — require frida marker nearby is already covered.
    }
    if (contains_ci(maps, "/data/local/tmp/") &&
        (contains_ci(maps, "frida") || contains_ci(maps, "gadget"))) {
        flags |= FLAG_INLINE_HOOK_HINT;
    }
    return flags;
}

int scan_threads() {
    DIR *dir = opendir("/proc/self/task");
    if (dir == nullptr) {
        return 0;
    }
    int flags = 0;
    while (dirent *entry = readdir(dir)) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        char path[256];
        std::snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
        const std::string name = read_file(path);
        if (contains_ci(name, "frida") || contains_ci(name, "gum-js") ||
            contains_ci(name, "gmain") || contains_ci(name, "pool-frida")) {
            flags |= FLAG_FRIDA_THREAD;
            break;
        }
    }
    closedir(dir);
    return flags;
}

int scan_files() {
    static const char *paths[] = {
        "/data/local/tmp/frida-server",
        "/data/local/tmp/re.frida.server",
        "/data/local/tmp/frida",
        "/sbin/.magisk",
    };
    for (const char *p : paths) {
        if (access(p, F_OK) == 0) {
            return FLAG_FRIDA_FILE;
        }
    }
    return 0;
}

int self_check() {
    return scan_maps() | scan_threads() | scan_files();
}

}  // namespace androidshield::anti_hook
