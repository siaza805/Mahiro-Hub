# Mahiro Hub

Single-file Roblox Luau build for direct HTTP loading.

```lua
loadstring(game:HttpGet("https://raw.githubusercontent.com/siaza805/Mahiro-Hub/main/MahiroHub.lua?v=obf-1"))()
```

The file starts automatically in a supported place. Stop an active run with `getgenv().KAITUN.stop()`.

The published distribution is encoded and decodes itself at runtime. Source obfuscation cannot protect code already visible in repository history or prevent inspection after runtime decoding.
