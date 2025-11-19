> [!WARNING]  
> This project is for **educational and research purposes only**.  
> The author is **not responsible** for bans or any damage.  
> **Use at your own risk.**

# Fall Guys Mod Menu
Android Fall Guys mod menu using [Frida](https://frida.re/) and [frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge)

For help, updates announcements, and additional platforms support, join our community in Discord:
[Make FG Great Again Discord Server](https://discord.gg/cNFJ73P6p3) 

## 📸 Showcase
![Demo](https://github.com/user-attachments/assets/57b9a4cd-3a62-47b7-8a3e-17dc801ea0b3)
<img src="https://github.com/user-attachments/assets/f2164534-1700-4ba6-b681-576dca29583d" width="500" height="224"/>

## ✨ Features

### Movement
- 360 Dives
- Air Jump
- Freeze Player
- Don't send Fall Guy state (packets)
- Change Speed
- Change Vertical Velocity / No Velocity / Negative Velocity
- Change Jump and Dive Strength

### Rounds helper
- Hide Real Doors (Door Dash and Lost Temple)
- Hide Fake Platforms (Tip Toe)

### Teleports
- Teleport To Finish or Crown
- Teleport To Bubble or Active Button

### Other
- View Names Shortcut
- Toggle Display UI
- Change FOV
- Display FGDebug
  - Shows FPS (min/max/avg/current), Time, Ping, Dropped Packets
- Change Resolution
- Disable FG Analytics 
- Show Number of Queued Players
- Show Game Details
  - Shows RoundID, seed and Eliminated Players
- Show Server Details
  - Shows Server IP, Host and Ping
- Show Build Info

### Features that always work (Always enabled)
- Bypass Character Physics Checks
- Remove FPS Limit
- Anti-AFK
- Bypass Permanent Ban (does not affect temporary bans)
- Automatically spoof to the latest game version
- Spoof Platform (requires manual script edit)
- Spoof Login, Gateway and analytics server (requires manual script edit)
  
## 📦 Installation
Just download and install the .apk from [Releases](https://github.com/repinek/fallguys-frida-modmenu/releases/latest)  
Not working? Look [🛠️ Troubleshooting](#%EF%B8%8F-troubleshooting)

> If you don't want to wait for game resources to download, copy the .obb file from:  
> Android/obb/com.Mediatonic.FallGuys_client/ to  
> Android/obb/com.Mediatonic.FallGuys_client.modmenu/,  
> then rename it by adding .modmenu before .obb  
> Final file name example: main.XXXX.com.mediatonic.FallGuys_client.modmenu.obb  

## 🛠️ Troubleshooting
> This project is for **educational and research purposes only**. I won't be providing support.

**Q:** Menu doesn't appear  
**A:** In The Main Menu it will ask for permission to display over other apps, If it doesn’t ask for it, grant it manually.   

**Q:** Emulator crashes  
**A:** Emulators are not supported.  

**HyperOS, ColorOS, OneUI, HarmonyOS**, and other **OEM ROMs** may not work properly or at all.   
**It is recommended to use ROMs with minimal changes to ART (mainly AOSP forks).**    

*Also frida or frida-il2cpp-bridge can be unstable.*

## 🏗️ Build
1. Clone the repository:
```
git clone https://github.com/repinek/fallguys-frida-modmenu
cd fallguys-frida-modmenu
```

**— Install dependencies** 
1. Make sure you have Python Installed. 
2. Install frida from requirements.txt
```
pip install -r requirements.txt
```

**— Build script**
1. Install dependencies:
``` 
npm install 
```
2. Create dist folder:
```
mkdir dist
```
3. Build the script
```
npm run build
```
Script will be saved at the path: ./dist/agent.js  

<!-- TODO: custom python script for it -->
**— Build APK**
1. Download Fall Guys Latest APK
2. Add permission to AndroidManifest.xml
```
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
```
3. Download frida-gadget for frida version from requirements.txt: [arm64](https://github.com/frida/frida/releases/download/17.5.1/frida-gadget-17.5.1-android-arm64.so.xz) (you need frida-gadget-FRIDA_VERSION-android-arm64.so.xz)
4. Install [frida-gadget injector](https://github.com/commonuserlol/fgi?tab=readme-ov-file#installing) (You can use any other way to inject frida-gadget to your APK)
5. Extract .so file and copy downloaded frida gadget to C:\Users\YOURUSER\\.fgi\arm64.so (rename it to arm64.so as well)
6. Inject frida-gadget
###### short command:
```
fgi -i <path_to_your_fall_guys.apk> -a arm64 -t script -l ./dist/agent.js --offline-mode
```
###### full command:
```
fgi -i <path_to_your_fall_guys.apk> -a arm64 -t script -l ./dist/agent.js -n libModMenu.so -s libModMenu.s.so --offline-mode
```
Apk will be saved as ./your_fall_guys.patched.apk 

## ⚙️ Debugging 
There's two way:   
**— Using frida-gadget (non root)**
1. Follow the instructions in [🏗️ Build](#%EF%B8%8F-build) up to the step with injecting frida-gadget  
2. Inject frida-gadget in your APK in listen mode instead script:
```
fgi -i <yourfallguys.apk> -a arm64 --offline-mode
```
3. Connect your android device using [ADB](https://developer.android.com/tools/adb)
4. Install and launch the apk then inject the script
```
npm run spawn
```
You will see frida console

**— Using frida-server (root)**
1. Refer [official Frida documentation](https://frida.re/docs/android/)

## 🤝 Contribution
Pull requests are welcome. Got ideas or questions? Join our [Discord!](https://discord.gg/cNFJ73P6p3)

## 🙏 Special Thanks
Obed Guys Team - Some features powered by **Obed Guys Team**  
[FloyzI](https://github.com/FloyzI) - For how the game works, help with some features, localization  
[commonuserlol](https://github.com/commonuserlol) - For help with code and [menu](https://github.com/commonuserlol/frida-java-menu)  
[Dynasty-Dev](https://github.com/Dynasty-Dev) - For testing & contribution  
[igamegod](https://github.com/igamegod) - For help with some features
