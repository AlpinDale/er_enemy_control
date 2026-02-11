#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>
#include <winuser.h>

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
constexpr uint32_t kDefaultTeamOffset = 0x6C;
constexpr uint32_t kDefaultTeamSize = 1;

constexpr uint32_t kChrInsChrCtrlOffset = 0x58;
constexpr uint32_t kChrCtrlOwnerOffset = 0x10;
constexpr uint32_t kChrCtrlModifierOffset = 0xC8;
constexpr uint32_t kChrCtrlModifierActionFlagsOffset = 0x18;
constexpr uint32_t kChrCtrlFlagsOffset = 0xF0;
constexpr uint32_t kChrCtrlTagOffset = 0x1A0;

constexpr uint32_t kActionDisableLockOnBit = 1u << 2;
constexpr uint32_t kActionDisableAbilityLockOnBit = 1u << 3;
constexpr uint32_t kCtrlDisableHitBit = 1u << 1;

constexpr uint32_t kFieldInsHandleOffset = 0x8;
constexpr uint32_t kWorldChrManMainPlayerOffset = 0x1E508;
constexpr uint32_t kChrInsFlags1c5Offset = 0x1C5;
constexpr uint32_t kChrInsDeathFlagBit = 1u << 7;
constexpr uint32_t kChrInsModuleContainerOffset = 0x190;
constexpr uint32_t kWorldChrManChrCamOffset = 0x1ECE0;
constexpr uint32_t kModuleContainerDataOffset = 0x0;
constexpr uint32_t kModuleContainerPhysicsOffset = 0x68;
constexpr uint32_t kChrDataHpOffset = 0x138;
constexpr uint32_t kChrDataMaxHpOffset = 0x13C;
constexpr uint32_t kChrDataMaxUncappedHpOffset = 0x140;
constexpr uint32_t kChrDataBaseHpOffset = 0x144;
constexpr uint32_t kCSCamFovOffset = 0x50;
constexpr uint32_t kChrPhysicsChrHitHeightOffset = 0x2D0;
constexpr uint32_t kChrPhysicsHitHeightOffset = 0x2E0;
constexpr uint32_t kChrCtrlScaleXOffset = 0x2D4;
constexpr uint32_t kChrCtrlScaleYOffset = 0x2D8;
constexpr uint32_t kChrCtrlScaleZOffset = 0x2DC;
constexpr float kCameraScaleMin = 1.25f;
constexpr float kCameraScaleFactor = 0.5f;
constexpr float kCameraMaxMultiplier = 1.8f;
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
std::atomic<bool> g_control_active{false};
HANDLE g_thread = nullptr;
char g_log_path[MAX_PATH * 4] = "erd_enemy_control.log";

struct TeamOverride {
  bool enabled = false;
  bool use_config = false;
  uint32_t offset = 0;
  uint32_t size = 1;
  uint32_t target_original = 0;
  bool target_has_original = false;
  uintptr_t target_ptr = 0;
  bool neutralize_player = true;
  uint32_t player_neutral_value = 0;
  uint32_t player_original = 0;
  bool player_has_original = false;
  uintptr_t player_ptr = 0;
};

TeamOverride g_team{
    false, false, kDefaultTeamOffset, kDefaultTeamSize, 0, false, 0, true, 0, 0,
    false, 0,
};

struct PlayerControlOverride {
  bool active = false;
  bool has_action_flags = false;
  bool has_ctrl_flags = false;
  uint32_t action_flags = 0;
  uint32_t ctrl_flags = 0;
};

PlayerControlOverride g_player_override;

struct HpSyncState {
  bool enabled = true;
  bool active = false;
  uintptr_t player_data = 0;
  uintptr_t target_data = 0;
  int32_t player_hp = 0;
  int32_t player_max_hp = 0;
  int32_t player_max_uncapped = 0;
  int32_t player_base_hp = 0;
};

HpSyncState g_hp_sync;

struct CameraOverrideState {
  bool enabled = true;
  bool active = false;
  float base_fov = 0.0f;
  float last_fov = 0.0f;
  float base_tag_y = 1.0f;
  float base_height = 0.0f;
  float min_scale = kCameraScaleMin;
  float scale_factor = kCameraScaleFactor;
  float max_multiplier = kCameraMaxMultiplier;
  uintptr_t chr_cam = 0;
};

CameraOverrideState g_camera;

uintptr_t g_active_target = 0;
uintptr_t g_active_player_chr = 0;
uintptr_t g_active_player_root = 0;

void align_player_to_target(uintptr_t actor_ctrl, uintptr_t player_ptr_addr);
void unlink_target(uintptr_t player_root);
void restore_team_override_config(uintptr_t target);
void set_control_flags(uintptr_t actor_mgr, uintptr_t actor_ctrl, bool enabled);
void start_hp_sync(uintptr_t player_chr, uintptr_t target);
void update_hp_sync();
void stop_hp_sync(const char *reason);
void start_camera_override(uintptr_t world_root, uintptr_t player_chr,
                           uintptr_t target);
void update_camera_override(uintptr_t target);
void stop_camera_override(const char *reason);

void log_msg(const char *msg) {
  OutputDebugStringA("[EREnemyControl] ");
  OutputDebugStringA(msg);
  OutputDebugStringA("\n");
}

void log_line(const char *fmt, ...) {
  FILE *f = std::fopen(g_log_path, "a");
  if (!f) {
    return;
  }
  std::fprintf(f, "[EREnemyControl] ");
  va_list args;
  va_start(args, fmt);
  std::vfprintf(f, fmt, args);
  va_end(args);
  std::fputc('\n', f);
  std::fclose(f);
}

void init_log_path(HMODULE module) {
  char buf[MAX_PATH * 4] = {};
  DWORD len = GetEnvironmentVariableA("ERD_LAUNCHER_DIR", buf,
                                      static_cast<DWORD>(sizeof(buf)));
  if (len > 0 && len < sizeof(buf)) {
    std::snprintf(g_log_path, sizeof(g_log_path), "%s\\erd_enemy_control.log",
                  buf);
    return;
  }

  if (!module) {
    return;
  }

  char mod_path[MAX_PATH * 4] = {};
  DWORD mod_len = GetModuleFileNameA(module, mod_path,
                                     static_cast<DWORD>(sizeof(mod_path)));
  if (mod_len == 0 || mod_len >= sizeof(mod_path)) {
    return;
  }
  std::string path(mod_path);
  size_t pos = path.find_last_of("\\/");
  if (pos == std::string::npos) {
    return;
  }
  std::string dir = path.substr(0, pos);
  std::snprintf(g_log_path, sizeof(g_log_path), "%s\\erd_enemy_control.log",
                dir.c_str());
}

std::string trim(const std::string &s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return std::string();
  }
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

bool parse_u32(const std::string &s, uint32_t &out) {
  if (s.empty()) {
    return false;
  }
  char *end = nullptr;
  unsigned long v = std::strtoul(s.c_str(), &end, 0);
  if (!end || end == s.c_str()) {
    return false;
  }
  out = static_cast<uint32_t>(v);
  return true;
}

bool parse_f32(const std::string &s, float &out) {
  if (s.empty()) {
    return false;
  }
  char *end = nullptr;
  float v = std::strtof(s.c_str(), &end);
  if (!end || end == s.c_str()) {
    return false;
  }
  out = v;
  return true;
}

void load_config() {
  g_team.enabled = true;
  g_team.use_config = false;
  g_team.offset = kDefaultTeamOffset;
  g_team.size = kDefaultTeamSize;
  g_team.neutralize_player = true;
  g_team.player_neutral_value = 0;
  g_team.target_has_original = false;
  g_team.player_has_original = false;
  g_team.target_ptr = 0;
  g_team.player_ptr = 0;
  g_hp_sync.enabled = true;
  g_camera.enabled = true;
  g_camera.base_tag_y = 1.0f;
  g_camera.base_height = 0.0f;
  g_camera.min_scale = kCameraScaleMin;
  g_camera.scale_factor = kCameraScaleFactor;
  g_camera.max_multiplier = kCameraMaxMultiplier;

  bool saw_enabled = false;
  bool saw_hp_sync = false;
  bool saw_camera_enabled = false;
  bool saw_camera_settings = false;
  FILE *f = std::fopen("erd_enemy_control.ini", "r");
  if (!f) {
    log_line("team override enabled (default)");
    log_line("hp sync enabled (default)");
    log_line("camera zoom enabled (default) min_scale=%.2f factor=%.2f "
             "max_mult=%.2f",
             g_camera.min_scale, g_camera.scale_factor,
             g_camera.max_multiplier);
    return;
  }
  g_team.use_config = true;
  char line[256] = {};
  while (std::fgets(line, sizeof(line), f)) {
    std::string s = trim(line);
    if (s.empty() || s[0] == '#' || s[0] == ';') {
      continue;
    }
    size_t eq = s.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    std::string key = trim(s.substr(0, eq));
    std::string val = trim(s.substr(eq + 1));
    uint32_t parsed = 0;
    if (key == "team_enabled" && parse_u32(val, parsed)) {
      g_team.enabled = (parsed != 0);
      saw_enabled = true;
    } else if (key == "team_offset" && parse_u32(val, parsed)) {
      g_team.offset = parsed;
    } else if (key == "team_size" && parse_u32(val, parsed)) {
      if (parsed == 1 || parsed == 2 || parsed == 4) {
        g_team.size = parsed;
      }
    } else if ((key == "player_neutralize" ||
                key == "team_player_neutralize") &&
               parse_u32(val, parsed)) {
      g_team.neutralize_player = (parsed != 0);
    } else if ((key == "player_neutral_value" ||
                key == "team_player_neutral_value") &&
               parse_u32(val, parsed)) {
      g_team.player_neutral_value = parsed;
    } else if ((key == "hp_sync" || key == "sync_player_hp") &&
               parse_u32(val, parsed)) {
      g_hp_sync.enabled = (parsed != 0);
      saw_hp_sync = true;
    } else if (key == "camera_enabled" && parse_u32(val, parsed)) {
      g_camera.enabled = (parsed != 0);
      saw_camera_enabled = true;
    } else if (key == "camera_scale_min" &&
               parse_f32(val, g_camera.min_scale)) {
      saw_camera_settings = true;
    } else if (key == "camera_scale_factor" &&
               parse_f32(val, g_camera.scale_factor)) {
      saw_camera_settings = true;
    } else if (key == "camera_scale_max" &&
               parse_f32(val, g_camera.max_multiplier)) {
      saw_camera_settings = true;
    }
  }
  std::fclose(f);

  if (g_team.enabled) {
    log_line(
        "%s team override enabled: offset=0x%x size=%u neutralize=%u value=%u",
        g_team.use_config ? "config" : "default", g_team.offset, g_team.size,
        g_team.neutralize_player ? 1u : 0u, g_team.player_neutral_value);
  } else if (saw_enabled) {
    log_line("team override disabled by config");
  } else {
    log_line("team override disabled (config present)");
  }

  if (g_hp_sync.enabled) {
    log_line("hp sync %s", saw_hp_sync ? "enabled (config)" : "enabled");
  } else {
    log_line("hp sync disabled (config)");
    if (g_hp_sync.active) {
      stop_hp_sync("config disabled");
    }
  }

  if (g_camera.enabled) {
    log_line("camera zoom %s min_scale=%.2f factor=%.2f max_mult=%.2f",
             (saw_camera_enabled || saw_camera_settings) ? "enabled (config)"
                                                         : "enabled",
             g_camera.min_scale, g_camera.scale_factor,
             g_camera.max_multiplier);
  } else {
    log_line("camera zoom disabled (config)");
    if (g_camera.active) {
      stop_camera_override("config disabled");
    }
  }
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

bool safe_read(uintptr_t addr, void *out, size_t size) {
  if (addr == 0 || out == nullptr || size == 0) {
    return false;
  }
#if defined(_MSC_VER)
  __try {
    std::memcpy(out, reinterpret_cast<const void *>(addr), size);
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
#else
  std::memcpy(out, reinterpret_cast<const void *>(addr), size);
  return true;
#endif
}

bool safe_read_ptr(uintptr_t addr, uintptr_t &out) {
  out = 0;
  return safe_read(addr, &out, sizeof(out));
}

int chr_ins_quality(uintptr_t ptr, uint8_t *team_out = nullptr) {
  if (!ptr) {
    return 0;
  }
  uint8_t team = 0;
  if (!safe_read(ptr + g_team.offset, &team, sizeof(team))) {
    return 0;
  }
  if (team > 77) {
    return 0;
  }
  uint32_t selector = 0;
  bool field_ok = false;
  if (safe_read(ptr + kFieldInsHandleOffset, &selector, sizeof(selector))) {
    uint32_t field_type = (selector >> 28) & 0xF;
    field_ok = (field_type == 1);
  }
  bool ctrl_ok = false;
  uintptr_t chr_ctrl = 0;
  if (safe_read_ptr(ptr + kChrInsChrCtrlOffset, chr_ctrl) && chr_ctrl) {
    uintptr_t owner = 0;
    if (safe_read_ptr(chr_ctrl + kChrCtrlOwnerOffset, owner) && owner == ptr) {
      ctrl_ok = true;
    }
  }
  if (team_out) {
    *team_out = team;
  }
  if (field_ok) {
    return 2;
  }
  if (ctrl_ok) {
    return 1;
  }
  return 0;
}

bool is_valid_chr_ins(uintptr_t ptr, uint8_t *team_out = nullptr) {
  return chr_ins_quality(ptr, team_out) > 0;
}

bool safe_write(uintptr_t addr, const void *data, size_t size) {
  if (addr == 0 || data == nullptr || size == 0) {
    return false;
  }
#if defined(_MSC_VER)
  __try {
    std::memcpy(reinterpret_cast<void *>(addr), data, size);
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
#else
  std::memcpy(reinterpret_cast<void *>(addr), data, size);
  return true;
#endif
}

uintptr_t resolve_player_chr(uintptr_t world_root, uintptr_t player_root,
                             uintptr_t actor_ctrl, uintptr_t target) {
  uintptr_t best = 0;
  int best_quality = 0;

  auto consider = [&](uintptr_t ptr) {
    if (!ptr || ptr == target) {
      return;
    }
    int q = chr_ins_quality(ptr);
    if (q > best_quality) {
      best_quality = q;
      best = ptr;
    }
  };

  consider(player_root);

  if (world_root) {
    uintptr_t main_player = 0;
    if (safe_read_ptr(world_root + kWorldChrManMainPlayerOffset, main_player)) {
      consider(main_player);
    }
  }

  if (actor_ctrl) {
    uintptr_t owner = 0;
    if (safe_read_ptr(actor_ctrl + kChrCtrlOwnerOffset, owner)) {
      consider(owner);
    }
  }

  if (player_root) {
    uintptr_t link_a = 0;
    if (safe_read_ptr(player_root + kLinkAOffset, link_a)) {
      consider(link_a);
    }
    uintptr_t link_b = 0;
    if (safe_read_ptr(player_root + kLinkBOffset, link_b)) {
      consider(link_b);
    }
    uintptr_t chr_ctrl = 0;
    if (safe_read_ptr(player_root + kChrInsChrCtrlOffset, chr_ctrl) &&
        chr_ctrl) {
      uintptr_t owner = 0;
      if (safe_read_ptr(chr_ctrl + kChrCtrlOwnerOffset, owner)) {
        consider(owner);
      }
    }

    for (uint32_t off = 0; off <= 0x200; off += 8) {
      uintptr_t ptr = 0;
      if (!safe_read_ptr(player_root + off, ptr)) {
        continue;
      }
      consider(ptr);
    }
  }

  if (best_quality > 0) {
    return best;
  }
  return 0;
}

uintptr_t resolve_chr_ctrl(uintptr_t chr_ins, uintptr_t fallback_ctrl) {
  if (chr_ins) {
    uintptr_t chr_ctrl = 0;
    if (safe_read_ptr(chr_ins + kChrInsChrCtrlOffset, chr_ctrl) && chr_ctrl) {
      return chr_ctrl;
    }
  }
  return fallback_ctrl;
}

uintptr_t resolve_chr_cam(uintptr_t world_root) {
  if (!world_root) {
    return 0;
  }
  uintptr_t chr_cam = 0;
  if (!safe_read_ptr(world_root + kWorldChrManChrCamOffset, chr_cam)) {
    return 0;
  }
  return chr_cam;
}

uintptr_t get_chr_data_module(uintptr_t chr_ins) {
  if (!chr_ins) {
    return 0;
  }
  uintptr_t container = 0;
  if (!safe_read_ptr(chr_ins + kChrInsModuleContainerOffset, container) ||
      !container) {
    return 0;
  }
  uintptr_t data = 0;
  if (!safe_read_ptr(container + kModuleContainerDataOffset, data) || !data) {
    return 0;
  }
  return data;
}

bool read_chr_hp(uintptr_t data, int32_t &hp, int32_t &max_hp,
                 int32_t &max_uncapped, int32_t &base_hp) {
  return safe_read(data + kChrDataHpOffset, &hp, sizeof(hp)) &&
         safe_read(data + kChrDataMaxHpOffset, &max_hp, sizeof(max_hp)) &&
         safe_read(data + kChrDataMaxUncappedHpOffset, &max_uncapped,
                   sizeof(max_uncapped)) &&
         safe_read(data + kChrDataBaseHpOffset, &base_hp, sizeof(base_hp));
}

bool write_chr_hp(uintptr_t data, int32_t hp, int32_t max_hp,
                  int32_t max_uncapped, int32_t base_hp) {
  return safe_write(data + kChrDataHpOffset, &hp, sizeof(hp)) &&
         safe_write(data + kChrDataMaxHpOffset, &max_hp, sizeof(max_hp)) &&
         safe_write(data + kChrDataMaxUncappedHpOffset, &max_uncapped,
                    sizeof(max_uncapped)) &&
         safe_write(data + kChrDataBaseHpOffset, &base_hp, sizeof(base_hp));
}

void apply_player_control_override(uintptr_t player_chr,
                                   uintptr_t fallback_ctrl) {
  g_player_override.active = false;
  g_player_override.has_action_flags = false;
  g_player_override.has_ctrl_flags = false;

  if (!is_valid_chr_ins(player_chr)) {
    log_line("player override: invalid player chr 0x%llx",
             static_cast<unsigned long long>(player_chr));
    return;
  }
  auto chr_ctrl = resolve_chr_ctrl(player_chr, fallback_ctrl);
  if (!chr_ctrl) {
    log_line("player override: chr_ctrl missing");
    return;
  }

  uintptr_t owner = 0;
  if (safe_read_ptr(chr_ctrl + kChrCtrlOwnerOffset, owner) && owner &&
      owner != player_chr) {
    log_line(
        "player override: chr_ctrl owner mismatch (owner=0x%llx chr=0x%llx)",
        static_cast<unsigned long long>(owner),
        static_cast<unsigned long long>(player_chr));
    return;
  }
  uintptr_t modifier = 0;
  safe_read_ptr(chr_ctrl + kChrCtrlModifierOffset, modifier);
  if (modifier) {
    uint32_t action_flags = 0;
    if (safe_read(modifier + kChrCtrlModifierActionFlagsOffset, &action_flags,
                  sizeof(action_flags))) {
      g_player_override.action_flags = action_flags;
      g_player_override.has_action_flags = true;
      action_flags |= kActionDisableLockOnBit;
      action_flags &= ~kActionDisableAbilityLockOnBit;
      if (safe_write(modifier + kChrCtrlModifierActionFlagsOffset,
                     &action_flags, sizeof(action_flags))) {
        log_line("player override: action_flags 0x%08x -> 0x%08x",
                 g_player_override.action_flags, action_flags);
      }
    }
  }

  uint32_t ctrl_flags = 0;
  if (safe_read(chr_ctrl + kChrCtrlFlagsOffset, &ctrl_flags,
                sizeof(ctrl_flags))) {
    g_player_override.ctrl_flags = ctrl_flags;
    g_player_override.has_ctrl_flags = true;
    ctrl_flags |= kCtrlDisableHitBit;
    if (safe_write(chr_ctrl + kChrCtrlFlagsOffset, &ctrl_flags,
                   sizeof(ctrl_flags))) {
      log_line("player override: ctrl_flags 0x%08x -> 0x%08x",
               g_player_override.ctrl_flags, ctrl_flags);
    }
  }

  g_player_override.active = true;
}

void start_hp_sync(uintptr_t player_chr, uintptr_t target) {
  if (!g_hp_sync.enabled) {
    return;
  }
  stop_hp_sync("restart");
  if (!is_valid_chr_ins(player_chr) || !is_valid_chr_ins(target)) {
    log_line("hp sync: invalid chr (player=0x%llx target=0x%llx)",
             static_cast<unsigned long long>(player_chr),
             static_cast<unsigned long long>(target));
    return;
  }
  uintptr_t player_data = get_chr_data_module(player_chr);
  uintptr_t target_data = get_chr_data_module(target);
  if (!player_data || !target_data) {
    log_line("hp sync: data module missing (player=0x%llx target=0x%llx)",
             static_cast<unsigned long long>(player_data),
             static_cast<unsigned long long>(target_data));
    return;
  }

  int32_t hp = 0;
  int32_t max_hp = 0;
  int32_t max_uncapped = 0;
  int32_t base_hp = 0;
  if (!read_chr_hp(player_data, hp, max_hp, max_uncapped, base_hp)) {
    log_line("hp sync: failed to read player hp");
    return;
  }

  g_hp_sync.player_data = player_data;
  g_hp_sync.target_data = target_data;
  g_hp_sync.player_hp = hp;
  g_hp_sync.player_max_hp = max_hp;
  g_hp_sync.player_max_uncapped = max_uncapped;
  g_hp_sync.player_base_hp = base_hp;
  g_hp_sync.active = true;

  log_line("hp sync enabled: player_hp=%d max=%d uncapped=%d base=%d", hp,
           max_hp, max_uncapped, base_hp);
}

void update_hp_sync() {
  if (!g_hp_sync.enabled || !g_hp_sync.active) {
    return;
  }
  if (!g_hp_sync.player_data || !g_hp_sync.target_data) {
    return;
  }

  int32_t hp = 0;
  int32_t max_hp = 0;
  int32_t max_uncapped = 0;
  int32_t base_hp = 0;
  if (!read_chr_hp(g_hp_sync.target_data, hp, max_hp, max_uncapped, base_hp)) {
    return;
  }

  if (max_hp < 1) {
    max_hp = 1;
  }
  if (max_uncapped < 1) {
    max_uncapped = max_hp;
  }
  if (base_hp < 1) {
    base_hp = max_hp;
  }
  if (hp < 1) {
    hp = 1;
  }
  write_chr_hp(g_hp_sync.player_data, hp, max_hp, max_uncapped, base_hp);
}

void stop_hp_sync(const char *reason) {
  if (!g_hp_sync.active) {
    return;
  }
  if (g_hp_sync.player_data) {
    write_chr_hp(g_hp_sync.player_data, g_hp_sync.player_hp,
                 g_hp_sync.player_max_hp, g_hp_sync.player_max_uncapped,
                 g_hp_sync.player_base_hp);
  }
  g_hp_sync.active = false;
  g_hp_sync.player_data = 0;
  g_hp_sync.target_data = 0;
  if (reason) {
    log_line("hp sync restored (%s)", reason);
  } else {
    log_line("hp sync restored");
  }
}

float read_chr_scale(uintptr_t chr_ins) {
  auto chr_ctrl = resolve_chr_ctrl(chr_ins, 0);
  if (!chr_ctrl) {
    return 1.0f;
  }
  float sx = 1.0f;
  float sy = 1.0f;
  float sz = 1.0f;
  if (!safe_read(chr_ctrl + kChrCtrlScaleXOffset, &sx, sizeof(sx)) ||
      !safe_read(chr_ctrl + kChrCtrlScaleYOffset, &sy, sizeof(sy)) ||
      !safe_read(chr_ctrl + kChrCtrlScaleZOffset, &sz, sizeof(sz))) {
    return 1.0f;
  }
  return std::max(sx, std::max(sy, sz));
}

float read_chr_tag_y(uintptr_t chr_ins) {
  auto chr_ctrl = resolve_chr_ctrl(chr_ins, 0);
  if (!chr_ctrl) {
    return 0.0f;
  }
  float y = 0.0f;
  if (!safe_read(chr_ctrl + kChrCtrlTagOffset + sizeof(float), &y, sizeof(y))) {
    return 0.0f;
  }
  return y;
}

float read_chr_height(uintptr_t chr_ins) {
  if (!chr_ins) {
    return 0.0f;
  }
  uintptr_t container = 0;
  if (!safe_read_ptr(chr_ins + kChrInsModuleContainerOffset, container) ||
      !container) {
    return 0.0f;
  }
  uintptr_t physics = 0;
  if (!safe_read_ptr(container + kModuleContainerPhysicsOffset, physics) ||
      !physics) {
    return 0.0f;
  }
  float height = 0.0f;
  if (safe_read(physics + kChrPhysicsHitHeightOffset, &height,
                sizeof(height)) &&
      height > 0.01f) {
    return height;
  }
  float chr_height = 0.0f;
  if (safe_read(physics + kChrPhysicsChrHitHeightOffset, &chr_height,
                sizeof(chr_height)) &&
      chr_height > 0.01f) {
    return chr_height;
  }
  return 0.0f;
}

void start_camera_override(uintptr_t world_root, uintptr_t player_chr,
                           uintptr_t target) {
  if (!g_camera.enabled) {
    return;
  }
  stop_camera_override("restart");
  auto chr_cam = resolve_chr_cam(world_root);
  if (!chr_cam) {
    log_line("camera zoom: chr_cam missing");
    return;
  }
  float fov = 0.0f;
  if (!safe_read(chr_cam + kCSCamFovOffset, &fov, sizeof(fov)) || fov <= 0.0f) {
    log_line("camera zoom: failed to read fov");
    return;
  }
  g_camera.chr_cam = chr_cam;
  g_camera.base_fov = fov;
  g_camera.last_fov = fov;
  float base_tag_y = read_chr_tag_y(player_chr);
  if (base_tag_y > 0.01f) {
    g_camera.base_tag_y = base_tag_y;
  } else {
    g_camera.base_tag_y = 1.0f;
  }
  g_camera.base_height = read_chr_height(player_chr);
  g_camera.active = true;
  update_camera_override(target);
}

void update_camera_override(uintptr_t target) {
  if (!g_camera.enabled || !g_camera.active || !g_camera.chr_cam) {
    return;
  }
  float scale = read_chr_scale(target);
  float tag_y = read_chr_tag_y(target);
  if (g_camera.base_tag_y > 0.01f && tag_y > 0.01f) {
    float tag_scale = tag_y / g_camera.base_tag_y;
    if (tag_scale > scale) {
      scale = tag_scale;
    }
  }
  if (g_camera.base_height > 0.01f) {
    float target_height = read_chr_height(target);
    if (target_height > 0.01f) {
      float height_scale = target_height / g_camera.base_height;
      if (height_scale > scale) {
        scale = height_scale;
      }
    }
  }
  float mult = 1.0f;
  if (scale > g_camera.min_scale) {
    mult = 1.0f + (scale - 1.0f) * g_camera.scale_factor;
    if (mult > g_camera.max_multiplier) {
      mult = g_camera.max_multiplier;
    }
  }
  float new_fov = g_camera.base_fov * mult;
  if (new_fov != g_camera.last_fov) {
    if (safe_write(g_camera.chr_cam + kCSCamFovOffset, &new_fov,
                   sizeof(new_fov))) {
      g_camera.last_fov = new_fov;
    }
  }
}

void stop_camera_override(const char *reason) {
  if (!g_camera.active) {
    return;
  }
  if (g_camera.chr_cam && g_camera.base_fov > 0.0f) {
    safe_write(g_camera.chr_cam + kCSCamFovOffset, &g_camera.base_fov,
               sizeof(g_camera.base_fov));
  }
  g_camera.active = false;
  g_camera.chr_cam = 0;
  g_camera.base_tag_y = 1.0f;
  g_camera.base_height = 0.0f;
  if (reason) {
    log_line("camera zoom restored (%s)", reason);
  } else {
    log_line("camera zoom restored");
  }
}

void restore_player_control_override(uintptr_t player_chr,
                                     uintptr_t fallback_ctrl) {
  if (!g_player_override.active) {
    return;
  }
  auto chr_ctrl = resolve_chr_ctrl(player_chr, fallback_ctrl);
  if (!chr_ctrl) {
    log_line("player override: chr_ctrl missing on restore");
    g_player_override.active = false;
    return;
  }
  uintptr_t modifier = 0;
  safe_read_ptr(chr_ctrl + kChrCtrlModifierOffset, modifier);
  if (modifier && g_player_override.has_action_flags) {
    if (safe_write(modifier + kChrCtrlModifierActionFlagsOffset,
                   &g_player_override.action_flags,
                   sizeof(g_player_override.action_flags))) {
      log_line("player override restored: action_flags 0x%08x",
               g_player_override.action_flags);
    }
  }

  if (g_player_override.has_ctrl_flags) {
    if (safe_write(chr_ctrl + kChrCtrlFlagsOffset,
                   &g_player_override.ctrl_flags,
                   sizeof(g_player_override.ctrl_flags))) {
      log_line("player override restored: ctrl_flags 0x%08x",
               g_player_override.ctrl_flags);
    }
  }

  g_player_override.active = false;
}

void release_control(uintptr_t world_root, uintptr_t actor_mgr,
                     uintptr_t actor_ctrl, uintptr_t player_ptr_addr,
                     const char *reason) {
  auto player_root = read_ptr(player_ptr_addr);
  if (!player_root) {
    player_root = g_active_player_root;
  }
  uintptr_t target = g_active_target;
  if (player_root) {
    align_player_to_target(actor_ctrl, player_ptr_addr);
    unlink_target(player_root);
  }

  if (g_team.enabled && target && is_valid_chr_ins(target)) {
    restore_team_override_config(target);
  } else {
    g_team.target_has_original = false;
    g_team.player_has_original = false;
  }

  auto player_chr = resolve_player_chr(world_root, player_root, actor_ctrl, 0);
  if (!player_chr) {
    player_chr = g_active_player_chr;
  }
  if (player_chr) {
    restore_player_control_override(player_chr, actor_ctrl);
  } else {
    g_player_override.active = false;
  }

  stop_hp_sync(reason);
  stop_camera_override(reason);

  set_control_flags(actor_mgr, actor_ctrl, false);
  g_control_active.store(false);
  g_active_target = 0;
  g_active_player_chr = 0;
  g_active_player_root = 0;
  if (reason) {
    log_line("control released (%s)", reason);
  }
}

bool capture_snapshot(uintptr_t base, size_t size, std::vector<uint8_t> &out) {
  out.resize(size);
  return safe_read(base, out.data(), size);
}

uint16_t read_u16(const std::vector<uint8_t> &data, size_t off) {
  return static_cast<uint16_t>(data[off]) |
         (static_cast<uint16_t>(data[off + 1]) << 8);
}

uint32_t read_u32(const std::vector<uint8_t> &data, size_t off) {
  return static_cast<uint32_t>(data[off]) |
         (static_cast<uint32_t>(data[off + 1]) << 8) |
         (static_cast<uint32_t>(data[off + 2]) << 16) |
         (static_cast<uint32_t>(data[off + 3]) << 24);
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

void align_player_to_target(uintptr_t actor_ctrl, uintptr_t player_ptr_addr) {
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
  write_f32(dst_transform + kPosYOffset, read_f32(src_transform + kPosYOffset));
  write_f32(dst_transform + kPosZOffset, read_f32(src_transform + kPosZOffset));
}

uintptr_t get_current_target(uintptr_t world_root, uintptr_t actor_mgr) {
  auto target_fn = reinterpret_cast<TargetFn>(g_addrs.target_fn_addr);
  if (!target_fn) {
    return 0;
  }
  void *target =
      target_fn(reinterpret_cast<void *>(world_root),
                reinterpret_cast<void *>(actor_mgr + kTargetContextOffset));
  return reinterpret_cast<uintptr_t>(target);
}

void scan_team_candidates(uintptr_t player_root, uintptr_t target_actor) {
  if (!player_root || !target_actor) {
    log_line("team scan: missing pointers (player=0x%llx target=0x%llx)",
             static_cast<unsigned long long>(player_root),
             static_cast<unsigned long long>(target_actor));
    return;
  }

  constexpr size_t kScanSize = 0x800;
  constexpr size_t kMaxCandidates = 200;
  std::vector<uint8_t> p1, t1, p2, t2;

  if (!capture_snapshot(player_root, kScanSize, p1) ||
      !capture_snapshot(target_actor, kScanSize, t1)) {
    log_line("team scan: snapshot failed");
    return;
  }

  Sleep(50);

  if (!capture_snapshot(player_root, kScanSize, p2) ||
      !capture_snapshot(target_actor, kScanSize, t2)) {
    log_line("team scan: snapshot2 failed");
    return;
  }

  log_line("=== team scan ===");
  log_line("player_root=0x%llx target=0x%llx size=0x%zx",
           static_cast<unsigned long long>(player_root),
           static_cast<unsigned long long>(target_actor), kScanSize);

  size_t count = 0;
  log_line("u8 candidates (<= 0x40):");
  for (size_t i = 0; i < kScanSize; ++i) {
    uint8_t pv = p1[i];
    uint8_t tv = t1[i];
    if (pv == tv) {
      continue;
    }
    if (pv != p2[i] || tv != t2[i]) {
      continue;
    }
    if (pv > 0x40 || tv > 0x40) {
      continue;
    }
    log_line("  +0x%03zx p=%u t=%u diff=0x%02x", i, pv, tv,
             static_cast<unsigned>(pv ^ tv));
    if (++count >= kMaxCandidates) {
      log_line("  ... truncated");
      break;
    }
  }

  count = 0;
  log_line("u16 candidates (<= 0x400):");
  for (size_t i = 0; i + 1 < kScanSize; ++i) {
    uint16_t pv = read_u16(p1, i);
    uint16_t tv = read_u16(t1, i);
    if (pv == tv) {
      continue;
    }
    if (pv != read_u16(p2, i) || tv != read_u16(t2, i)) {
      continue;
    }
    if (pv > 0x400 || tv > 0x400) {
      continue;
    }
    log_line("  +0x%03zx p=%u t=%u diff=0x%04x", i, pv, tv,
             static_cast<unsigned>(pv ^ tv));
    if (++count >= kMaxCandidates) {
      log_line("  ... truncated");
      break;
    }
  }

  count = 0;
  log_line("u32 candidates (<= 0x10000):");
  for (size_t i = 0; i + 3 < kScanSize; ++i) {
    uint32_t pv = read_u32(p1, i);
    uint32_t tv = read_u32(t1, i);
    if (pv == tv) {
      continue;
    }
    if (pv != read_u32(p2, i) || tv != read_u32(t2, i)) {
      continue;
    }
    if (pv > 0x10000 || tv > 0x10000) {
      continue;
    }
    log_line("  +0x%03zx p=%u t=%u diff=0x%08x", i, pv, tv,
             static_cast<unsigned>(pv ^ tv));
    if (++count >= kMaxCandidates) {
      log_line("  ... truncated");
      break;
    }
  }

  log_line("=== end team scan ===");
}

void log_team_values(const char *tag, uintptr_t player_root, uintptr_t target) {
  uint32_t pval = 0;
  uint32_t tval = 0;
  bool okp = safe_read(player_root + g_team.offset, &pval, g_team.size);
  bool okt = safe_read(target + g_team.offset, &tval, g_team.size);
  log_line("%s team values: player=0x%llx %s=%u target=0x%llx %s=%u off=0x%x "
           "size=%u",
           tag, static_cast<unsigned long long>(player_root),
           okp ? "val" : "read_fail", okp ? pval : 0,
           static_cast<unsigned long long>(target), okt ? "val" : "read_fail",
           okt ? tval : 0, g_team.offset, g_team.size);
}

void scan_team_ptr_candidates(uintptr_t base, const char *label) {
  if (!base) {
    log_line("team ptr scan: %s base null", label);
    return;
  }
  log_line("=== team ptr scan (%s) base=0x%llx ===", label,
           static_cast<unsigned long long>(base));
  uint32_t direct = 0;
  if (safe_read(base + g_team.offset, &direct, g_team.size)) {
    log_line("  direct +0x%x => %u", g_team.offset, direct);
  } else {
    log_line("  direct +0x%x => read failed", g_team.offset);
  }
  for (uint32_t off = 0; off <= 0x200; off += 8) {
    uintptr_t ptr = read_ptr(base + off);
    if (!ptr) {
      continue;
    }
    uint8_t val = 0;
    int quality = chr_ins_quality(ptr, &val);
    if (quality > 0) {
      log_line("  +0x%03x -> 0x%llx team=%u quality=%d", off,
               static_cast<unsigned long long>(ptr), val, quality);
    }
  }
  log_line("=== end team ptr scan (%s) ===", label);
}

void debug_team_scan(uintptr_t world_root, uintptr_t actor_mgr,
                     uintptr_t player_ptr_addr) {
  auto player_root = read_ptr(player_ptr_addr);
  if (!player_root) {
    log_line("team scan: player_root null");
    return;
  }

  if (world_root) {
    uintptr_t main_player = 0;
    if (safe_read_ptr(world_root + kWorldChrManMainPlayerOffset, main_player)) {
      uint8_t team = 0;
      int quality = chr_ins_quality(main_player, &team);
      log_line("team scan: world_root main_player=0x%llx team=%u quality=%d",
               static_cast<unsigned long long>(main_player), team, quality);
    } else {
      log_line("team scan: world_root main_player read failed");
    }
  }

  uintptr_t target = read_ptr(player_root + kLinkBOffset);
  if (!target) {
    target = get_current_target(world_root, actor_mgr);
  }
  if (!target) {
    log_line("team scan: no target (lock on first)");
    return;
  }
  scan_team_candidates(player_root, target);
  scan_team_ptr_candidates(player_root, "player_root");
  scan_team_ptr_candidates(target, "target");
}

void apply_team_override_config(uintptr_t player_root, uintptr_t target) {
  if (!g_team.enabled) {
    return;
  }
  if (!is_valid_chr_ins(player_root)) {
    log_line("team override: invalid player chr 0x%llx",
             static_cast<unsigned long long>(player_root));
    return;
  }
  if (!is_valid_chr_ins(target)) {
    log_line("team override: invalid target chr 0x%llx",
             static_cast<unsigned long long>(target));
    return;
  }
  uint32_t player_val = 0;
  uint32_t target_val = 0;
  if (safe_read(player_root + g_team.offset, &player_val, g_team.size) &&
      safe_read(target + g_team.offset, &target_val, g_team.size)) {
    g_team.target_original = target_val;
    g_team.target_has_original = true;
    g_team.target_ptr = target;
    g_team.player_original = player_val;
    g_team.player_has_original = true;
    g_team.player_ptr = player_root;
    if (safe_write(target + g_team.offset, &player_val, g_team.size)) {
      log_line("team override (config): off=0x%x size=%u player=%u target=%u",
               g_team.offset, g_team.size, player_val, target_val);
    } else {
      log_line("team override (config): write failed at off=0x%x",
               g_team.offset);
    }
    if (g_team.neutralize_player) {
      uint32_t neutral = g_team.player_neutral_value;
      if (safe_write(player_root + g_team.offset, &neutral, g_team.size)) {
        log_line("team override (config): neutralized player value=%u",
                 neutral);
      } else {
        log_line("team override (config): player neutralize failed at off=0x%x",
                 g_team.offset);
      }
    }
  } else {
    log_line("team override (config): read failed at off=0x%x", g_team.offset);
  }
}

void restore_team_override_config(uintptr_t target) {
  if (!g_team.enabled) {
    return;
  }
  if (g_team.target_has_original) {
    uintptr_t restore_target = g_team.target_ptr ? g_team.target_ptr : target;
    if (restore_target && is_valid_chr_ins(restore_target) &&
        safe_write(restore_target + g_team.offset, &g_team.target_original,
                   g_team.size)) {
      log_line("team override restored (config): off=0x%x size=%u value=%u "
               "target=0x%llx",
               g_team.offset, g_team.size, g_team.target_original,
               static_cast<unsigned long long>(restore_target));
    } else {
      log_line("team override restore failed (config) at off=0x%x",
               g_team.offset);
    }
  }
  if (g_team.neutralize_player && g_team.player_has_original) {
    uintptr_t restore_player = g_team.player_ptr;
    if (restore_player && is_valid_chr_ins(restore_player) &&
        safe_write(restore_player + g_team.offset, &g_team.player_original,
                   g_team.size)) {
      log_line("team override restored player: value=%u player=0x%llx",
               g_team.player_original,
               static_cast<unsigned long long>(restore_player));
    } else {
      log_line("team override restore failed (player) at off=0x%x",
               g_team.offset);
    }
  }
  g_team.target_has_original = false;
  g_team.player_has_original = false;
  g_team.target_ptr = 0;
  g_team.player_ptr = 0;
}

void handle_f1(uintptr_t world_root, uintptr_t actor_mgr, uintptr_t actor_ctrl,
               uintptr_t player_ptr_addr) {
  uintptr_t target = get_current_target(world_root, actor_mgr);
  if (!target) {
    return;
  }

  auto player_root = read_ptr(player_ptr_addr);
  auto player_chr =
      resolve_player_chr(world_root, player_root, actor_ctrl, target);
  if (player_root) {
    if (player_chr) {
      if (player_chr != player_root) {
        log_line("player chr resolved: root=0x%llx chr=0x%llx",
                 static_cast<unsigned long long>(player_root),
                 static_cast<unsigned long long>(player_chr));
      }
      log_team_values("before override", player_chr, target);
    } else {
      log_line("player chr unresolved (root=0x%llx)",
               static_cast<unsigned long long>(player_root));
    }
    link_target(player_root, target);
  }

  if (g_team.enabled && player_chr) {
    apply_team_override_config(player_chr, target);
    log_team_values("after override", player_chr, target);
  }

  if (player_chr) {
    apply_player_control_override(player_chr, actor_ctrl);
  }
  if (player_chr) {
    start_hp_sync(player_chr, target);
  }
  start_camera_override(world_root, player_chr, target);

  set_control_flags(actor_mgr, actor_ctrl, true);
  g_control_active.store(true);
  g_active_target = target;
  g_active_player_chr = player_chr;
  g_active_player_root = player_root;
}

void handle_f2(uintptr_t world_root, uintptr_t actor_mgr, uintptr_t actor_ctrl,
               uintptr_t player_ptr_addr) {
  release_control(world_root, actor_mgr, actor_ctrl, player_ptr_addr, "manual");
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
    handle_f2(world_root, actor_mgr, actor_ctrl, g_addrs.player_ptr_addr);
  } else if (GetAsyncKeyState(VK_F3) & 1) {
    debug_team_scan(world_root, actor_mgr, g_addrs.player_ptr_addr);
  } else if (GetAsyncKeyState(VK_F4) & 1) {
    load_config();
  }

  if (g_control_active.load()) {
    auto player_root = read_ptr(g_addrs.player_ptr_addr);
    uintptr_t target = 0;
    if (player_root) {
      target = read_ptr(player_root + kLinkBOffset);
    }
    if (!target) {
      target = g_active_target;
    }
    bool should_release = false;
    if (!target || !is_valid_chr_ins(target)) {
      should_release = true;
    } else {
      auto flags = read_u8(target + kChrInsFlags1c5Offset);
      if (flags & kChrInsDeathFlagBit) {
        should_release = true;
      }
    }
    if (should_release) {
      release_control(world_root, actor_mgr, actor_ctrl,
                      g_addrs.player_ptr_addr, "target gone");
    }
  }

  if (g_control_active.load()) {
    uintptr_t target = 0;
    auto player_root = read_ptr(g_addrs.player_ptr_addr);
    if (player_root) {
      target = read_ptr(player_root + kLinkBOffset);
    }
    if (!target) {
      target = g_active_target;
    }
    update_camera_override(target);
    update_hp_sync();
    set_control_flags(actor_mgr, actor_ctrl, true);
  }

  sync_position(actor_mgr, actor_ctrl, g_addrs.player_ptr_addr);
}

DWORD WINAPI mod_thread(LPVOID) {
  load_config();
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
    init_log_path(module);
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
