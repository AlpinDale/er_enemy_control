#pragma once

#include <cstddef>
#include <cstdint>

namespace pattern_scan {

uint8_t *find_pattern(uint8_t *base, size_t size, const uint8_t *pattern,
                      const char *mask);
uintptr_t resolve_rel32(uint8_t *instr, int offset = 3, int instr_len = 7);

} // namespace pattern_scan
