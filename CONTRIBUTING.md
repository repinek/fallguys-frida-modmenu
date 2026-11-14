# Contributing to Fall Guys Frida Mod Menu

Thank you for your interest in this project! We welcome any contributions, such as bug fixes, new features or localization improvements.

> [!WARNING]
> This project is for educational and research purposes only. The author is not responsible for bans or any damage. Use at your own risk.

#### Contents

- [Prerequisites](#prerequisites)
- [Setup & Building](#Setup--Building)
- [Developing](#developing)
- [Available npm Scripts](#available-npm-scripts)
- [Project Structure](#project-structure)
- [Pull Request Process](#pull-request-process)
- [Helpful Information & Resources](#Helpful-information--Resources)

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

## Setup & Building

0. Environment setup and dependencies

- Download the latest Fall Guys APK from the Epic Games Store and save it as `data/Fall_Guys_<VERSION>.apk`.
- If you are using **[Nix](https://nixos.org)**, simply run:

```bash
nix develop

# Install dependencies for Python
python -m pip install -r requirements.txt

# Install script dependencies for node.js
npm install
```

- If you are not using Nix:

```bash
 # Creating a virtual environment for Python
 python -m venv .venv

 # Activate Python venv, it's depending on what OS you are. For example on Linux:
 . .venv/bin/activate

 # Install dependencies for python
 pip install -r requirements.txt

 # Install script dependencies for node.js
 npm install
```

1. Preparing the APK

Patch it with APKEditor: add the overlay permission and rename the package to `com.Mediatonic.FallGuys_client.modmenu` so the mod installs alongside the original game.

```bash
java -jar APKEditor.jar d -i data/Fall_Guys_<VERSION>.apk -o data/edited

# add to AndroidManifest.xml:
#   <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
# change package to com.Mediatonic.FallGuys_client.modmenu
java -jar APKEditor.jar b -i data/edited -o data/Fall_Guys_<VERSION>_perm.apk
```

2. Build the script

Build the script into `dist/agent.js`:

```bash
npm run build:release
```

3. Patch APK using frida gadget in **script mode**

```bash
objection patchapk -s data/Fall_Guys_<VERSION>_perm.apk -c objection.cfg.json -l dist/agent.js
```

Patched APK will be saved with `.objection` suffix

> **Tip regarding OBB files:**  
> If you don't want to wait for game resources to download again:
>
> 1. Copy the `.obb` file from `Android/obb/com.Mediatonic.FallGuys_client/`.
> 2. Create a new folder: `Android/obb/com.Mediatonic.FallGuys_client.modmenu/`.
> 3. Paste the file there and rename it by adding `.modmenu` before `.obb`.  
>    _Example:_ `main.XXXX.com.mediatonic.FallGuys_client.modmenu.obb`

On the first launch the game will ask for the "Display over other apps" permission.

## Developing

These instructions are for developers who want to modify the script and test changes dynamically without rebuilding and reinstalling the APK every time.

0. Environment setup and dependencies

Follow steps 0 and 1 from [Setup & Building](#Setup-&-Building)

1. Patch APK using frida gadget in **listen mode**

```bash
objection patchapk -s data/Fall_Guys_<VERSION>_perm.apk
```

Patched APK will be saved with `.objection` suffix

2. Install APK on your android device

```bash
adb install data/Fall_Guys_<VERSION>_perm.objection.apk
```

3. Spawn script

Open patched apk on your device and run

```
npm run spawn:dev
```

## Available npm Scripts

Scripts are defined in [package.json](package.json).

### Build

These scripts build the agent into `./dist/agent.js` using Webpack:

- `npm run build` – Builds a **RELEASE** version (minified, optimized)
- `npm run build:dev` – Builds a **DEVELOPMENT** version (with debug logs and debug UI)

### Spawn

> **Prerequisites:** Requires a patched APK with Frida Gadget configured in **listen** mode.  
> Your device should be connected via ADB

- `npm run spawn` – Injects the compiled `dist/agent.js` into the connected device.
- `npm run spawn:dev` – Runs `build:dev` and `spawn`.
- `npm run spawn:release` – Runs `build:release` and `spawn`.

### Code Quality & Formatting

- `npm run prettier` – Formats the codebase using [Prettier](https://prettier.io/).
- `npm run lint` – Runs [ESLint](https://eslint.org/) to perform static code analysis and fix issues via the `--fix` flag.

## Project Structure

**MAY BE OUTDATED**

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

You can read more information here: [GitHub "Pull request" documentation](https://docs.github.com/en/pull-requests/reference/pull-requests) and [GitHub "Creating a pull request" documentation](https://docs.github.com/en/pull-requests/how-tos/create-pull-requests/creating-a-pull-request)

## Helpful information / Resources

### Mono Code Leaks

Fall Guys has several leaks of development builds with **Mono** DLLs.  
These are extremely useful for analyzing game logic and class structures in clean C# before they are compiled to IL2CPP.

We maintain a FG Archive with these builds. **A Telegram account is required to download them.**

- **v4.5.0** (5 May 2021) — [Download Link](https://t.me/FallGuysBuilds/34)
- **v9.0.4** (1 March 2023) — [Download Link](https://t.me/FallGuysBuilds/203)
- **v10.7.0 Developer Mono Build** (28 November 2023) — [Download Link](https://t.me/FallGuysBuilds/201)
- **Other Builds** — [FG Archive Website](https://obed-guys-corp.github.io/fg-archive)
    - _(Note: You can also download older builds via Steam Depots if you own the game on Steam)_

All managed DLLs are stored in `FallGuys_client_BackUpThisFolder_ButDontShipItWithYourGame/Managed` folder.

### Reverse Engineering Tools

- [Il2CppInspectorRedux](https://github.com/LukeFZ/Il2CppInspectorRedux) - Generating the python script to rename functions and apply structs in disassemblers.
- IDA Pro, Ghidra or Binary Ninja - Required for analyzing Android-specific logic, and game versions newer than the last Mono leak (10.7+).
- [dnSpyEx](https://github.com/dnSpyEx/dnSpy) or [ILSpy](https://github.com/icsharpcode/ILSpy) - For viewing C# DLLs (From Mono builds).
- [UnityExplorer](https://github.com/sinai-dev/UnityExplorer) - BepInEx & MelonLoader mod for in-game exploring, debugging and modifying unity games.
- Any network debugger - For analyzing HTTPs traffic.

### Docs

- [Frida Documentation](https://frida.re/docs/) - General Frida API reference.
- [Unity Scripting Documentation](https://docs.unity3d.com/ScriptReference/index.html) - Reference for Unity classes (GameObject, Transform, etc...).
- [frida-il2cpp-bridge Wiki](https://github.com/vfsfitvnm/frida-il2cpp-bridge/wiki) - Specific API for the IL2CPP used in this project.
- [APKEditor](https://github.com/REAndroid/APKEditor) - Powerful Android APK editor
- [objection Patching Guide](https://github.com/sensepost/objection/wiki/Patching-Android-Applications)
