#include "crypto.h"
#include "integrity.h"

#include <algorithm>
#include <vector>

namespace androidshield::crypto {

bool unscramble_key(
        const uint8_t *scrambled,
        size_t scrambled_len,
        const uint8_t *seed,
        size_t seed_len,
        std::vector<uint8_t> *out) {
    if (scrambled == nullptr || seed == nullptr || out == nullptr || scrambled_len == 0) {
        return false;
    }
    out->assign(scrambled_len, 0);
    size_t produced = 0;
    int counter = 0;
    while (produced < scrambled_len) {
        // mask block = SHA256(seed || counter_byte)
        std::vector<uint8_t> material(seed, seed + seed_len);
        material.push_back(static_cast<uint8_t>(counter & 0xff));
        uint8_t digest[32];
        if (!androidshield::integrity::sha256(material.data(), material.size(), digest)) {
            return false;
        }
        const size_t to_copy = std::min(sizeof(digest), scrambled_len - produced);
        for (size_t i = 0; i < to_copy; ++i) {
            (*out)[produced + i] = static_cast<uint8_t>(scrambled[produced + i] ^ digest[i]);
        }
        produced += to_copy;
        ++counter;
    }
    return true;
}

}  // namespace androidshield::crypto
