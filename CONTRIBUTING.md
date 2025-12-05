# Contributing to Fall Guys Frida Mod Menu

Thank you for your interest in this project! We welcome any contributions: bug fixes, new features or documentation improvements.

Please read this guide before you start coding.

> [!WARNING]  
> This project is for **educational and research purposes only**.  
> The author is **not responsible** for bans or any damage. 


## Table of Contents
- [Prerequisites](#prerequisites)
- [Setup & Installation](#setup--installation)
    - [Building the APK](#building-the-apk)
- [Development Workflow](#development-workflow)
- [Available Scripts](#available-scripts)
- [Project Structure](#project-structure)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)


## Prerequisites
- Python >=3.10 for frida & fgi
- Node.js
- Android Device (You **DON'T** need root)
- [Android Debug Bridge](https://developer.android.com/tools/adb)  

For apk building:
- Android Studio or Android Build tools
- Java Development Kit

\
## Setup & Installation
There are two steps: building the script and building the APK.

1. Clone the repository:
```bash
git clone https://github.com/repinek/fallguys-frida-modmenu
cd fallguys-frida-modmenu
```

2. Install the required version of Frida: 
```bash
pip install -r requirements.txt
```

3. Install Node.js dependencies (for script)
```bash
npm install
```

### Building the APK
To run the mod, you need to patch the game APK. You can do this in two modes: 
1. **Script Mode** (for users)
2. **Listen Mode** (for developers)

#### 1. Prepare APK
1. Obtain the latest Fall Guys APK.
2. Use an APK Editor to add the overlay permission to `AndroidManifest.xml`. Without this, the menu UI will not render.
```xml
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
```
3. Optional: you can change the package name and application name.

#### 2. Patching with Frida Gadget
I recommend using [frida-gadget-injector (fgi)](https://github.com/commonuserlol/fgi),
but you can use any other way to inject script.

1. Download frida-gadget from frida-releases:  
    *Note: Ensure the gadget version matches the `frida` version in `requirements.txt`.*  
    v16.7.19:
    * [arm.so.xz](https://github.com/frida/frida/releases/download/16.7.19/frida-gadget-16.7.19-android-arm.so.xz)
    * [arm64.so.xz](https://github.com/frida/frida/releases/download/16.7.19/frida-gadget-16.7.19-android-arm64.so.xz)
2. Extract the downloaded libraries and rename it to `arm.so` and `arm64.so`.
3. Place `.so` files into `fgi` configuration folder.  
    For Windows it's: C:\Users\%USERPROFILE%\\.fgi\\

#### Development Build: 
Injects Frida in `listen` mode. The game will pause at startup until you manually inject the script.
```bash
fgi -i <path_to_apk> --offline-mode
```

#### Release Build: 
Injects Frida in `script` mode. Frida will load the script itself.
The script is located in ./dist/agent.js.
```bash
npm run build:release
fgi -i <path_to_apk> -t script -l ./dist/agent.js -n libModMenu.so -s libModMenu.s.so --offline-mode
```

> **Note:**  
> If you are running `fgi` for the first time, offline mode may fail due to missing dependencies.  
> To fix this:
> 1. Run `fgi` **without** `--offline-mode` once to let it download the necessary base files.
> 2. Replace the gadget files in the `.fgi` folder with the specific versions (16.7.19) you downloaded above.
> 3. Run the command again **with** `--offline-mode`.


## Development Workflow
If you are modifying the code, use this workflow to avoid rebuilding the APK constantly:

1. Install the **Development Build** APK on your device.
2. Grant permission to "Display over other apps" in your Android settings. When you first spawn the menu, it will ask you for this permission.
3. Connect your device via ADB.
4. Compile script & spawn 
```bash
npm run spawn:dev
```
Look for [Available Scripts](#available-scripts).

## Available Scripts

**Build the script:**  
Compile the agent into `./dist/agent.js`.  
```npm run build:release``` - a **RELEASE** version (minified, optimized, no logs).  
```npm run build:staging``` - a **STAGING** version.  
```npm run build:dev``` - a **DEV** version.

**Build & run script:**  
Builds the script and immediately inject script into the game with the gadget.  
```npm run spawn:release``` - a **RELEASE** version.  
```npm run spawn:staging``` - a **STAGING** version.  
```npm run spawn:dev``` - a **DEV** version.  

**Watch script**  
```npm run watch``` - Watches a DEV version.  

**Run script:**   
```npm run spawn``` - Just spawns script in gadget-mode.  

**Code quality:**  
```npm run lint``` - Runs [eslint](https://eslint.org/) to check for errors.  
```npm run prettier``` - Runs [prettier](https://prettier.io/) to format code.  

\* from package.


## Project Structure
```text
fallguys-frida-modmenu/
├── src/
│   ├── index.ts                # Entry Point
│   ├── core/
│   │   ├── BaseModule.ts       # Abstract base class for all modules (Extend this!)
│   │   ├── ModuleManager.ts    # Module initialization
│   │   └── AssemblyHelper.ts   # Manages IL2CPP assemblies
│   ├── data/                   # Defaults, Layouts & Preferences
│   ├── i18n/                   # Internationalization system
│   │   └── localization/       # JSON translation files
│   ├── logger/                 # Custom logger implementation
│   ├── modules/                # Mod features categorized
│   │   ├── game/               # Internal game features
│   │   ├── network/            # Network related
│   │   ├── player/             # Player movement & physics
│   │   ├── rounds/             # Level-specific logic (DoorManager, TipToeManager...)
│   │   └── visuals/            # Visual changes (FGDebug, FPS Bypass, etc.)
│   ├── ui/                     # Menu interface
│   │   ├── menu/               # Main menu construction (using frida-java-menu)
│   │   └── popup/              # Wrapper for In-Game PopupManager
│   │       └── data/           # Wrappers for Popups classes
│   └── utils/                  # Helper functions
│       ├── JavaUtils.ts        # Java-bridge helper functions
│       └── UnityUtils.ts       # Unity / IL2CPP helper functions
├── eslint.config.mts           # ESLint config
├── package.json                # Node.js dependencies & scripts
├── requirements.txt            # Python dependencies
├── tsconfig.json               # TypeScript configuration
└── webpack.config.js           # Webpack compiler config
```

## Code Style

We enforce code style using **ESLint** and **Prettier**.  
**Please run `npm run lint` before submitting a PR.**

### Naming Conventions
- **Classes & Files:** `PascalCase` (e.g., `PopupManager.ts`, `UICanvasModule`).
- **Methods & Properties:** `camelCase` (e.g., `toggleNames`, `initHooks`).
- **Private & Cached Fields:** Use the `_` prefix (e.g., `_popupManagerInstance`).
- **Constants:** `UPPER_SNAKE_CASE` (e.g., `TELEPORT_COOLDOWN`).
- **Interfaces:** Prefix with `I` (e.g., `IClientDetails`).
- **Game/Unity Code:** Keep original naming for Unity classes and methods to match the game's assembly (e.g., `FallGuysCharacterController`, `TheMultiplayerGuys.FGCommon`).

### Typing
We rely on TypeScript to catch errors before runtime.
*   **No `any`:** Avoid using `any` type. It defeats the purpose of TypeScript. Excludes is ...parameters and errors.
*   **Use Il2Cpp Types:** Always use specific types from `frida-il2cpp-bridge` (e.g., `Il2Cpp.Class`, `Il2Cpp.String`, `Il2Cpp.Object`).
*   **Interfaces:** Define interfaces for JSON responses or complex objects (see `IClientDetails` in `Catapult.ts`).
*   **Return Types:** Explicitly define return types for methods.
*   **@ts-ignore:** Use //@ts-ignore for hooks where you need to specify types of arguments: [Explanation](https://github.com/vfsfitvnm/frida-il2cpp-bridge/wiki/Changelog#v090).
*   **Do not worry about this alias:** I mean [this](https://typescript-eslint.io/rules/no-this-alias/).

```ts
// Good
//@ts-ignore
this.WebSocketNetworkHostCtor.implementation = function (serverAddress: Il2Cpp.String, port: number, isSecure: boolean): void { ... }

GameManagerInstance.field<Il2Cpp.Object>("_round").value;
```

### Logging Standard 
*   **Tagging:** Every class should have a `tag` or `name` property.
*   **Format:** `[${this.tag}::MethodName] Message`.
*   **No Console:** Never use `console.log`. Use `Logger`.
*   **Hook Logs:** Add `Logger.hook` to hooks, **excluding** high-frequency methods.

```ts
// Good
private static readonly tag = "UnityUtils";

Logger.info(`[${this.tag}::init] Initialized`);
Logger.warn(`[${this.tag}::someFetchFunc] Can't fetch info about something`);
Logger.errorThrow(error, "Failed to do something");
```

### Documentation (JSDoc)
We have documentation for:
*   Public methods.
*   Complex logic / hooks.
*   Wrappers around IL2CPP classes.

```ts
// Good
/** Wrapper over UnityEngine::Object::FindObjectsOfType */
static FindObjectsOfType(klass: Il2Cpp.Class): Il2Cpp.Array<Il2Cpp.Object> { ... }
```

### IL2CPP Wrappers
*   Create wrappers for classes, methods instead calling of `.method().invoke()` everywhere.
*   Reuse existing wrappers in `src/utils/`.

### Internationalization (i18n)
Do not hardcode strings for UI or Toasts.
*   Use `I18n.t("tab.key_name")`.
*   Add translations to `src/i18n/localization/lang.json`.

### Imports Organization
Group imports in the same way as the structure to keep the file header clean.

```ts
// Good
import { BaseModule } from "../../core/BaseModule";
import { CatapultModule } from "../modules/network/Catapult";
import { Logger } from "../../logger/Logger";
```
