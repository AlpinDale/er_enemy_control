#include "pattern_scan.h"

#include <cstring>

namespace pattern_scan {

uint8_t *find_pattern(uint8_t *base, size_t size, const uint8_t *pattern,
                      const char *mask) {
  if (!base || !pattern || !mask) {
    return nullptr;
  }

  const size_t mask_len = std::strlen(mask);
  if (mask_len == 0 || size < mask_len) {
    return nullptr;
  }

  for (size_t i = 0; i <= size - mask_len; ++i) {
    bool match = true;
    for (size_t j = 0; j < mask_len; ++j) {
      if (mask[j] == 'x' && base[i + j] != pattern[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      return base + i;
    }
  }

  return nullptr;
}

uintptr_t resolve_rel32(uint8_t *instr, int offset, int instr_len) {
  if (!instr) {
    return 0;
  }

  const int32_t rel = *reinterpret_cast<int32_t *>(instr + offset);
  return reinterpret_cast<uintptr_t>(instr + instr_len + rel);
}

} // namespace pattern_scan
