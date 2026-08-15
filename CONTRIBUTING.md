# Contributing to Fall Guys Frida Mod Menu

Thank you for your interest in this project! We welcome any contributions, such as bug fixes, new features or localization improvements.

> [!WARNING]
> This project is for educational and research purposes only. The author is not responsible for bans or any damage. Use at your own risk.

#### Contents
- [Prerequisites](#prerequisites)
- [Setup & Installation](#setup--installation)
- [Preparing the APK](#preparing-the-apk)
- [Building](#building)
- [Developing](#developing)
- [Available npm Scripts](#available-npm-scripts)
- [Conventions](#conventions)
- [Project Structure](#project-structure)
- [Pull Request Process](#pull-request-process)
- [Resources](#resources)

## Prerequisites

If you are using [Nix](https://nixos.org/), you can use the provided [flake.nix](flake.nix) to automatically set up the development shell. Otherwise, make sure you have installed:

- git
- [Python 3.10+](https://www.python.org/) (3.14 is recommended)
- [Node.js](https://nodejs.org/)
- [JDK](https://www.oracle.com/java/technologies/downloads/)
- [APKEditor](https://github.com/REAndroid/APKEditor/releases/latest)
- [Android SDK Build Tools](https://developer.android.com/studio) (`zipalign`, `apksigner`)
- Android device (root is not required)
- [Android Debug Bridge (ADB)](https://developer.android.com/tools/adb)

## Setup & Installation

```bash
git clone https://github.com/repinek/fallguys-frida-modmenu
cd fallguys-frida-modmenu

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
npm install
```

## Preparing the APK

Download the latest Fall Guys APK from the Epic Games Store and save it as `data/Fall_Guys_<VERSION>.apk`.

Patch it with APKEditor: add the overlay permission and rename the package to `com.Mediatonic.FallGuys_client.modmenu` so the mod installs alongside the original game.

```bash
java -jar APKEditor.jar d -i data/Fall_Guys_<VERSION>.apk -o data/edited

# add to AndroidManifest.xml:
#   <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
# change package to com.Mediatonic.FallGuys_client.modmenu
java -jar APKEditor.jar b -i data/edited -o data/Fall_Guys_<VERSION>_perm.apk
```

## Building

Script mode: the script is embedded into the APK and runs automatically on launch.

```bash
npm run build:release

objection patchapk -s data/Fall_Guys_<VERSION>_perm.apk -c objection.cfg.json -l dist/agent.js
```

> **Tip regarding OBB files:**  
> If you don't want to wait for game resources to download again:
> 1. Copy the `.obb` file from `Android/obb/com.Mediatonic.FallGuys_client/`.
> 2. Create a new folder: `Android/obb/com.Mediatonic.FallGuys_client.modmenu/`.
> 3. Paste the file there and rename it by adding `.modmenu` before `.obb`.  
> *Example:* `main.XXXX.com.mediatonic.FallGuys_client.modmenu.obb`

On the first launch the game will ask for the "Display over other apps" permission.

## Developing

Use listen mode while modifying the script, so you don't have to rebuild and reinstall the APK on every change. The game pauses at startup and waits for the script to be injected manually.

```bash
objection patchapk -s data/Fall_Guys_<VERSION>_perm.apk
adb install data/Fall_Guys_<VERSION>_perm.objection.apk

# build a dev script and inject it into the paused game
npm run spawn:dev
```

## Available npm Scripts

Scripts are defined in [package.json](package.json).

### Build

Build the agent into `./dist/agent.js`:

- `npm run build:release` - a release version (minified, optimized)
- `npm run build:dev` - a dev version (with logs and debug UI)
- `npm run watch` - a dev version, rebuilds on file changes

### Spawn

> **Prerequisites:** a listen-mode patched APK, a device connected via ADB and the Frida CLI installed (`requirements.txt`).

- `npm run spawn:dev` - builds a dev version and injects it
- `npm run spawn:release` - builds a release version and injects it
- `npm run spawn` - injects the existing `dist/agent.js`
- `npm run spawn:server` - injects via frida-server

### Code Quality & Formatting

- `npm run lint` - runs [ESLint](https://eslint.org/)
- `npm run prettier` - runs [Prettier](https://prettier.io/)

## Conventions

- Files and classes are `PascalCase`, methods and properties are `camelCase`, private/cached fields use a `_` prefix, constants are `UPPER_SNAKE_CASE`, interfaces use an `I` prefix.
- Use [frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge) types where possible instead of `any`.
- Use `Logger` instead of `console.log` and tag messages as `[ModuleName::MethodName] message`.
- Development-only code goes inside `/// #if DEV` blocks, it is stripped from release builds.
- Don't hardcode UI strings or toasts; add them to `src/i18n/localization/en.json` and `ru.json` and use `I18n.t("...")`.
- In hooks `this` is the game instance; keep a `const module = this` reference and use `//@ts-ignore` for explicit hook argument types if needed.
- For Il2Cpp calls prefer the wrappers in `src/utils/` over bare `.method(...).invoke()` calls.

## Project Structure

```text
fallguys-frida-modmenu/
├── src/
│   ├── index.ts                # Entry Point
│   │
│   ├── core/                   # Module system
│   │   ├── BaseModule.ts       # Abstract base class for all modules
│   │   ├── ModuleManager.ts    # Module registration and initialization
│   │   └── AssemblyHelper.ts   # Cached IL2CPP assemblies
│   │
│   ├── data/                   # Preferences, settings, defaults and layout
│   │
│   ├── i18n/                   # Internationalization
│   │   └── localization/       # JSON translation files (en.json, ru.json)
│   │
│   ├── logger/                 # Logger and Unity log redirect
│   │
│   ├── modules/                # Mod features
│   │   ├── game/
│   │   ├── network/
│   │   ├── player/
│   │   ├── rounds/
│   │   └── visuals/
│   │
│   ├── ui/
│   │   ├── menu/               # Menu construction (frida-java-menu)
│   │   └── popup/              # Wrapper for the in-game popup manager
│   │
│   └── utils/                  # Java and Unity helpers
│
├── objection.cfg.json          # Frida gadget config (script mode)
├── eslint.config.mts
├── flake.nix
├── package.json
├── requirements.txt
├── tsconfig.json
└── webpack.config.mts
```

## Pull Request Process

We use [Conventional Commits](https://www.conventionalcommits.org/): `<type>(optional scope): <description>`.

1. **Fork** the repository
2. **Create** a feature branch (e.g. `<your_nickname>/add-feature`)
3. **Make** your changes
4. **Commit** your changes
5. **Push** to your branch
6. **Open** a pull request

## Helpful information / Resources
### Mono Code Leaks
Fall Guys has several leaks of development builds with **Mono** DLLs.  
These are extremely useful for analyzing game logic and class structures in clean C# before they are compiled to IL2CPP.

We maintain a FG Archive with these builds. **A Telegram account is required to download them.**
*   **v4.5.0** (5 May 2021) — [Download Link](https://t.me/FallGuysBuilds/34)
*   **v9.0.4** (1 March 2023) — [Download Link](https://t.me/FallGuysBuilds/203)
*   **v10.7.0 Developer Mono Build** (28 November 2023) — [Download Link](https://t.me/FallGuysBuilds/201)
*   **Other Builds** — [FG Archive Website](https://obed-guys-corp.github.io/fg-archive)
    *   *(Note: You can also download older builds via Steam Depots if you own the game on Steam)*

All managed DLLs are stored in `FallGuys_client_BackUpThisFolder_ButDontShipItWithYourGame/Managed` folder.
### Reverse Engineering Tools
*   [Il2CppDumper-GUI](https://github.com/AndnixSH/Il2CppDumper-GUI) - Generating `dump.cs`. Use this to quickly view class structures, fields, and method signatures.
*   [Il2CppInspectorRedux](https://github.com/LukeFZ/Il2CppInspectorRedux) - Generating the python script to rename functions and apply structs in disassemblers.
*   IDA Pro, Ghidra or Binary Ninja - Required for analyzing Android-specific logic, and game versions newer than the last Mono leak (10.7+).
*   [dnSpyEx](https://github.com/dnSpyEx/dnSpy) or [ILSpy](https://github.com/icsharpcode/ILSpy) - For viewing C# DLLs (From Mono builds).
*   [UnityExplorer](https://github.com/sinai-dev/UnityExplorer) - BepInEx & MelonLoader mod for in-game exploring, debugging and modifying unity games.
*   Any network debugger - For analyzing HTTPs traffic.

### Docs
*   [Frida Documentation](https://frida.re/docs/) - General Frida API reference. 
*   [Unity Scripting Documentation](https://docs.unity3d.com/ScriptReference/index.html) - Reference for Unity classes (GameObject, Transform, etc...).
*   [frida-il2cpp-bridge Wiki](https://github.com/vfsfitvnm/frida-il2cpp-bridge/wiki) - Specific API for the IL2CPP used in this project.
*   [APKEditor](https://github.com/REAndroid/APKEditor) - Powerful Android APK editor 
*   [objection Patching Guide](https://github.com/sensepost/objection/wiki/Patching-Android-Applications) 
