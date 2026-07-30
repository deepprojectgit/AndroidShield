#include "anti_debug.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

namespace androidshield::anti_debug {
namespace {

bool read_file(const char *path, std::string *out) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in) {
        return false;
    }
    out->assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

}  // namespace

int check_tracer_pid() {
    std::string status;
    if (!read_file("/proc/self/status", &status)) {
        return 0;
    }
    const char *key = "TracerPid:";
    const auto pos = status.find(key);
    if (pos == std::string::npos) {
        return 0;
    }
    int pid = 0;
    if (std::sscanf(status.c_str() + pos + std::strlen(key), "%d", &pid) == 1 && pid > 0) {
        return FLAG_TRACER_PID;
    }
    return 0;
}

int check_ptrace() {
    // Attempt to attach to ourselves — fails if already traced.
    errno = 0;
    const long result = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
    if (result == -1 && errno == EPERM) {
        return FLAG_PTRACE;
    }
    if (result == 0) {
        // Detach / allow future attach attempts by clearing TRACEME if supported.
        ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    }
    return 0;
}

int check_debugger_ports() {
    // Common Frida default / JDWP-ish local listeners (best-effort connect).
    const int ports[] = {27042, 27043, 23946};
    for (int port : ports) {
        const int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            continue;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        const int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        const int rc = connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        close(fd);
        if (rc == 0 || errno == EISCONN || errno == EALREADY) {
            return FLAG_DEBUGGER_PORT;
        }
        // EINPROGRESS may still indicate a live listener; treat rare successes as signal.
        if (errno == EINPROGRESS) {
            // Incomplete — ignore to reduce false positives.
        }
    }
    return 0;
}

int check_timing() {
    using clock = std::chrono::steady_clock;
    const auto start = clock::now();
    volatile int x = 0;
    for (int i = 0; i < 200000; ++i) {
        x ^= i;
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start);
    // Very loose bound; catches heavy single-stepping, not normal variance.
    if (x >= 0 && elapsed.count() > 200) {
        return FLAG_TIMING;
    }
    return 0;
}

int self_check() {
    return check_tracer_pid() | check_ptrace() | check_debugger_ports() | check_timing();
}

}  // namespace androidshield::anti_debug
