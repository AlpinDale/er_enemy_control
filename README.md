# Elden Ring Enemy Control

A clean-room implementation of the [Enemy control](https://www.nexusmods.com/eldenring/mods/1590) mod.

## Usage
- F1: attach player control to a target NPC.
- F2: release control and restore state.
- F3: dump team-field candidates to `erd_enemy_control.log` (debug helper).
- F4: reload `erd_enemy_control.ini` (team override config).

## Build (Windows, MSVC)

```
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
```

The output DLL will be `build/dist/EnemyControl/elden_ring_enemy_control.dll`.
The launcher will be `build/dist/erd_launcher.exe`.
The launcher writes `erd_launcher.log` in its working directory.
The mod writes `erd_enemy_control.log` in the launcher directory.

## Optional config (`erd_enemy_control.ini`)
```
# Team override (defaults shown)
team_enabled=1
team_offset=0x6c
team_size=1
team_player_neutralize=1
team_player_neutral_value=0

# Sync player HP to controlled NPC (1=on, 0=off)
hp_sync=1

# Camera zoom scaling for large NPCs
camera_enabled=1
camera_scale_min=1.25
camera_scale_factor=0.5
camera_scale_max=1.8
```
