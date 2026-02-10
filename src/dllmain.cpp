#include <atomic>
#include <cstdint>
#include <windows.h>

#include "pattern_scan.h"

namespace {

struct Addresses {
  uint8_t *base = nullptr;
  size_t size = 0;
  uintptr_t world_ptr_addr = 0;
  uintptr_t player_ptr_addr = 0;
  uintptr_t target_fn_addr = 0;
};

using TargetFn = void *(__fastcall *)(void *world, void *context);

constexpr uint32_t kWorldRootOffset = 0x10EF8;
constexpr uint32_t kActorCtrlOffset = 0x190;
constexpr uint32_t kActorCtrlTransformOffset = 0x68;
constexpr uint32_t kActorStateOffset = 0x68;
constexpr uint32_t kActorFlags0Offset = 0x530;
constexpr uint32_t kActorFlags1Offset = 0x1C5;
constexpr uint32_t kTargetContextOffset = 0x6B0;

constexpr uint32_t kLinkAOffset = 0xA8;
constexpr uint32_t kLinkBOffset = 0xB8;
constexpr uint32_t kBackLinkOffset = 0x3B0;

constexpr uint32_t kInnerCtrlFlagOffset = 0x19B;
constexpr uint32_t kTransformFlagOffset = 0x1D3;

constexpr uint32_t kPosXOffset = 0x70;
constexpr uint32_t kPosYOffset = 0x74;
constexpr uint32_t kPosZOffset = 0x78;

constexpr float kYOffset = -0.875f;

const uint8_t kSigWorldPtr[] = {0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48,
                                0x85, 0xC0, 0x74, 0x00, 0x48, 0x39, 0x88, 0x00,
                                0x00, 0x00, 0x00, 0x75, 0x00, 0x89, 0xB1, 0x6C,
                                0x03, 0x00, 0x00, 0x0F, 0x28, 0x05, 0x00, 0x00,
                                0x00, 0x00, 0x4C, 0x8D, 0x45, 0xE7};
const char kMaskWorldPtr[] = "xxx????xxxx?xxx????x?xxxxxxxxx????xxxx";

const uint8_t kSigPlayerPtr[] = {0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x89,
                                 0x5C, 0x24, 0x20, 0x48, 0x85, 0xC9, 0x74, 0x12,
                                 0xB8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0xD8};
const char kMaskPlayerPtr[] = "xxx????xxxxxxxxxx????xx";

const uint8_t kSigTargetFn[] = {0x48, 0x83, 0xEC, 0x28, 0xE8, 0x00,
                                0x00, 0x00, 0x00, 0x48, 0x85, 0xC0,
                                0x74, 0x00, 0x48, 0x8B, 0x00};
const char kMaskTargetFn[] = "xxxxx????xxxx?xxx";

Addresses g_addrs;
std::atomic<bool> g_stop{false};
HANDLE g_thread = nullptr;

void log_msg(const char *msg) {
  OutputDebugStringA("[EREnemyControl] ");
  OutputDebugStringA(msg);
  OutputDebugStringA("\n");
}

uintptr_t read_ptr(uintptr_t addr) {
  if (addr == 0) {
    return 0;
  }
  return *reinterpret_cast<uintptr_t *>(addr);
}

void write_ptr(uintptr_t addr, uintptr_t value) {
  if (addr == 0) {
    return;
  }
  *reinterpret_cast<uintptr_t *>(addr) = value;
}

uint8_t read_u8(uintptr_t addr) {
  if (addr == 0) {
    return 0;
  }
  return *reinterpret_cast<uint8_t *>(addr);
}

void write_u8(uintptr_t addr, uint8_t value) {
  if (addr == 0) {
    return;
  }
  *reinterpret_cast<uint8_t *>(addr) = value;
}

int32_t read_i32(uintptr_t addr) {
  if (addr == 0) {
    return 0;
  }
  return *reinterpret_cast<int32_t *>(addr);
}

void write_i32(uintptr_t addr, int32_t value) {
  if (addr == 0) {
    return;
  }
  *reinterpret_cast<int32_t *>(addr) = value;
}

float read_f32(uintptr_t addr) {
  if (addr == 0) {
    return 0.0f;
  }
  return *reinterpret_cast<float *>(addr);
}

void write_f32(uintptr_t addr, float value) {
  if (addr == 0) {
    return;
  }
  *reinterpret_cast<float *>(addr) = value;
}

bool resolve_addresses() {
  g_addrs.base = reinterpret_cast<uint8_t *>(GetModuleHandleA("eldenring.exe"));
  if (!g_addrs.base) {
    log_msg("eldenring.exe not loaded");
    return false;
  }

  auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(g_addrs.base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    log_msg("Invalid DOS header");
    return false;
  }

  auto nt =
      reinterpret_cast<IMAGE_NT_HEADERS64 *>(g_addrs.base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    log_msg("Invalid NT header");
    return false;
  }

  g_addrs.size = nt->OptionalHeader.SizeOfImage;
  if (g_addrs.size == 0) {
    log_msg("Invalid image size");
    return false;
  }

  uint8_t *sig1 = pattern_scan::find_pattern(g_addrs.base, g_addrs.size,
                                             kSigWorldPtr, kMaskWorldPtr);
  if (!sig1) {
    log_msg("Sig1 not found");
    return false;
  }
  g_addrs.world_ptr_addr = pattern_scan::resolve_rel32(sig1);

  uint8_t *sig2 = pattern_scan::find_pattern(g_addrs.base, g_addrs.size,
                                             kSigPlayerPtr, kMaskPlayerPtr);
  if (!sig2) {
    log_msg("Sig2 not found");
    return false;
  }
  g_addrs.player_ptr_addr = pattern_scan::resolve_rel32(sig2);

  uint8_t *sig3 = pattern_scan::find_pattern(g_addrs.base, g_addrs.size,
                                             kSigTargetFn, kMaskTargetFn);
  if (!sig3) {
    log_msg("Sig3 not found");
    return false;
  }
  g_addrs.target_fn_addr = reinterpret_cast<uintptr_t>(sig3);

  return true;
}

void link_target(uintptr_t player_root, uintptr_t target_actor) {
  if (!player_root || !target_actor) {
    return;
  }

  auto link_a = read_ptr(player_root + kLinkAOffset);
  auto link_b = read_ptr(player_root + kLinkBOffset);

  if (link_b) {
    auto link_b58 = read_ptr(link_b + 0x58);
    if (link_b58) {
      write_ptr(link_b58 + kBackLinkOffset, 0);
    }
    write_ptr(player_root + kLinkBOffset, 0);
  }

  if (link_a) {
    write_ptr(link_a + kLinkAOffset, target_actor);
  }

  auto target58 = read_ptr(target_actor + 0x58);
  if (target58) {
    write_ptr(target58 + kBackLinkOffset, link_a);
  }
  write_ptr(player_root + kLinkBOffset, target_actor);
}

void unlink_target(uintptr_t player_root) {
  if (!player_root) {
    return;
  }

  auto link_b = read_ptr(player_root + kLinkBOffset);
  if (link_b) {
    auto link_b58 = read_ptr(link_b + 0x58);
    if (link_b58) {
      write_ptr(link_b58 + kBackLinkOffset, 0);
    }
    write_ptr(player_root + kLinkBOffset, 0);
  }

  auto link_a = read_ptr(player_root + kLinkAOffset);
  if (link_a) {
    write_ptr(link_a + kLinkAOffset, 0);
  }
}

void set_control_flags(uintptr_t actor_mgr, uintptr_t actor_ctrl,
                       bool enabled) {
  if (!actor_mgr || !actor_ctrl) {
    return;
  }

  auto flags0 = read_u8(actor_mgr + kActorFlags0Offset);
  auto flags1 = read_u8(actor_mgr + kActorFlags1Offset);
  if (enabled) {
    write_u8(actor_mgr + kActorFlags0Offset,
             static_cast<uint8_t>(flags0 | 0x30));
    write_u8(actor_mgr + kActorFlags1Offset,
             static_cast<uint8_t>(flags1 & ~0x08));
  } else {
    write_u8(actor_mgr + kActorFlags0Offset,
             static_cast<uint8_t>(flags0 & ~0x30));
    write_u8(actor_mgr + kActorFlags1Offset,
             static_cast<uint8_t>(flags1 | 0x08));
  }

  auto inner_ctrl = read_ptr(actor_ctrl);
  if (inner_ctrl) {
    auto inner_flags = read_u8(inner_ctrl + kInnerCtrlFlagOffset);
    if (enabled) {
      write_u8(inner_ctrl + kInnerCtrlFlagOffset,
               static_cast<uint8_t>(inner_flags | 0x01));
    } else {
      write_u8(inner_ctrl + kInnerCtrlFlagOffset,
               static_cast<uint8_t>(inner_flags & ~0x01));
    }
  }

  auto ctrl_transform = read_ptr(actor_ctrl + kActorCtrlTransformOffset);
  if (ctrl_transform) {
    write_u8(ctrl_transform + kTransformFlagOffset, enabled ? 1 : 0);
  }
  write_i32(actor_mgr + kActorStateOffset, enabled ? 5 : 0);
}

void sync_position(uintptr_t actor_mgr, uintptr_t actor_ctrl,
                   uintptr_t player_ptr_addr) {
  auto player_root = read_ptr(player_ptr_addr);
  if (!player_root) {
    return;
  }

  auto link_b = read_ptr(player_root + kLinkBOffset);
  if (!link_b) {
    return;
  }

  auto src_ctrl = read_ptr(link_b + kActorCtrlOffset);
  if (!src_ctrl) {
    return;
  }

  auto src_transform = read_ptr(src_ctrl + kActorCtrlTransformOffset);
  auto dst_transform = read_ptr(actor_ctrl + kActorCtrlTransformOffset);
  if (!src_transform || !dst_transform) {
    return;
  }

  write_f32(dst_transform + kPosXOffset, read_f32(src_transform + kPosXOffset));
  write_f32(dst_transform + kPosYOffset,
            read_f32(src_transform + kPosYOffset) + kYOffset);
  write_f32(dst_transform + kPosZOffset, read_f32(src_transform + kPosZOffset));
}

void handle_f1(uintptr_t world_root, uintptr_t actor_mgr, uintptr_t actor_ctrl,
               uintptr_t player_ptr_addr) {
  auto target_fn = reinterpret_cast<TargetFn>(g_addrs.target_fn_addr);
  if (!target_fn) {
    return;
  }

  void *target =
      target_fn(reinterpret_cast<void *>(world_root),
                reinterpret_cast<void *>(actor_mgr + kTargetContextOffset));
  if (!target) {
    return;
  }

  auto player_root = read_ptr(player_ptr_addr);
  if (player_root) {
    link_target(player_root, reinterpret_cast<uintptr_t>(target));
  }

  set_control_flags(actor_mgr, actor_ctrl, true);
}

void handle_f2(uintptr_t actor_mgr, uintptr_t actor_ctrl,
               uintptr_t player_ptr_addr) {
  auto player_root = read_ptr(player_ptr_addr);
  if (player_root) {
    unlink_target(player_root);
  }

  set_control_flags(actor_mgr, actor_ctrl, false);
}

void tick() {
  auto world_root = read_ptr(g_addrs.world_ptr_addr);
  if (!world_root) {
    return;
  }

  auto world_data = read_ptr(world_root + kWorldRootOffset);
  if (!world_data) {
    return;
  }

  auto actor_mgr = read_ptr(world_data);
  if (!actor_mgr) {
    return;
  }

  auto actor_ctrl = read_ptr(actor_mgr + kActorCtrlOffset);
  if (!actor_ctrl) {
    return;
  }

  if (GetAsyncKeyState(VK_F1) & 1) {
    handle_f1(world_root, actor_mgr, actor_ctrl, g_addrs.player_ptr_addr);
  } else if (GetAsyncKeyState(VK_F2) & 1) {
    handle_f2(actor_mgr, actor_ctrl, g_addrs.player_ptr_addr);
  }

  sync_position(actor_mgr, actor_ctrl, g_addrs.player_ptr_addr);
}

DWORD WINAPI mod_thread(LPVOID) {
  if (!resolve_addresses()) {
    log_msg("Address resolution failed");
    return 0;
  }

  log_msg("Initialized");
  while (!g_stop.load()) {
    tick();
    Sleep(10);
  }

  log_msg("Stopping");
  return 0;
}

} // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(module);
    g_thread = CreateThread(nullptr, 0, mod_thread, nullptr, 0, nullptr);
  } else if (reason == DLL_PROCESS_DETACH) {
    g_stop.store(true);
    if (g_thread) {
      CloseHandle(g_thread);
      g_thread = nullptr;
    }
  }
  return TRUE;
}
