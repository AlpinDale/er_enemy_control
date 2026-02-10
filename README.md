# Elden Ring Enemy Control

A clean-room implementation of the [Enemy control](https://www.nexusmods.com/eldenring/mods/1590) mod.

## Usage
- F1: attach player control to a target NPC.
- F2: release control and restore state.
- F3: dump team-field candidates to `erd_enemy_control.log` (debug helper).
- F4: reload `erd_enemy_control.ini` (team override config).
- Continuous position sync while controlled (with a small Y-offset).

## Build (Windows, MSVC)

```
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
```

The output DLL will be `build/dist/EnemyControl/elden_ring_enemy_control.dll`.
The launcher will be `build/dist/erd_launcher.exe`.

## Launcher
```
erd_launcher.exe eldenring.exe EnemyControl\\elden_ring_enemy_control.dll
```

Auto-detection:
- If you omit the EXE path, the launcher will try to locate Steam's library folders and use the default Elden Ring install path.

Logging:
- The launcher writes `erd_launcher.log` in its working directory.

## Team override (experimental)
The mod changes teams by default. It copies the player's team to the controlled NPC and (optionally) neutralizes
the player while controlling. The defaults are:

```
team_enabled=1
team_offset=0x6C
team_size=1
player_neutralize=1
player_neutral_value=0
```

If you want to override these or disable the behavior entirely, create
`erd_enemy_control.ini` in the game folder:

```
team_enabled=1
team_offset=0x6C
team_size=1
player_neutralize=1
player_neutral_value=0
```

Set `team_enabled=0` to disable the override. Press F4 to reload the config while
the game is running.
