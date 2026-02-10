# Elden Ring Enemy Control

A clean-room implementation of the [Enemy control](https://www.nexusmods.com/eldenring/mods/1590) mod.

## Usage
- F1: attach player control to a target NPC.
- F2: release control and restore state.
- Continuous position sync while controlled (with a small Y-offset).

## Build (Windows, MSVC)

```
cmake -S . -B build -A x64
cmake --build build --config Release
```

The output DLL will be `build/Release/erd_enemy_control.dll`.
The launcher will be `build/Release/erd_launcher.exe`.
