> [!WARNING]  
> This project is for educational purposes only.  
> The author is not responsible for any bans from the use of this tool!  
> Use it at your own risk.

# Fall Guys Mod Menu
Android Fall Guys mod menu using [Frida](https://frida.re/) and [frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge) <br>

For help, updates announcements, and additional platforms support, join our community in Discord:
[Make FG Great Again Discord Server](https://discord.gg/cNFJ73P6p3) 

## 📸 Screenshots
![Demo](https://github.com/user-attachments/assets/57b9a4cd-3a62-47b7-8a3e-17dc801ea0b3)

<img src="https://github.com/user-attachments/assets/59ddff53-6dc1-49cc-8396-4243bb3c096a" width="500" height="224"/>
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
- Show Number of Queued Players
- Show Game Details
  - Shows RoundID, seed and Eliminated Players
- Show Server Details
  - Shows Server IP, Host and Ping
- Show Build Info

### Features that always work (cannot be disabled)
- Bypass Character Physics Checks
- Remove FPS Limit
- Anti-AFK
- Bypass Permanent Ban (does not affect temporary bans)
- Automatically spoof to the latest game version
- Spoof Platform (requires manual script edit)
- Spoof Login, Gateway and analytics server (requires manual script edit)
  
## 📦 Installation
Just download and install the .apk from [Releases](https://github.com/repinek/fallguys-frida-modmenu/releases/latest) <br>
Not working? Look [🛠️ Troubleshooting](#%EF%B8%8F-troubleshooting)

> If you don't want to wait for game resources to download, copy the .obb file from: <br>
> Android/obb/com.Mediatonic.FallGuys_client/ to <br>
> Android/obb/com.Mediatonic.FallGuys_client.modmenu/, then rename it by adding .modmenu before .obb <br>
> Final file name example: main.XXXX.com.mediatonic.FallGuys_client.modmenu.obb <br>

## 🛠️ Troubleshooting
> This project is created only for educational and entertainment purposes. I won't be providing support.

In The Main Menu it will ask for permission to display over other apps, If it doesn’t ask for it, grant it manually. <br><br>
**HyperOS, ColorOS, OneUI, HarmonyOS**, and other OEM ROMs may not work properly or at all. <br>
**It is recommended to use ROMs with minimal changes to ART (mainly AOSP forks).** <br>
**EMULATORS ARE NOT SUPPORTED!!** <br> <br>
Also frida and frida-il2cpp-bridge can be unstable. 

## 🏗️ Build
**— Install dependencies**
1. Make sure you have Python Installed. 
2. Install Frida-Tools 13.6.1
```
pip install frida-tools==13.6.1
```
That should install frida 16.7.19 too <br>

**— Build script**
1. Clone the repository:
```
git clone https://github.com/repinek/fallguys-frida-modmenu
cd fallguys-frida-modmenu
```
2. Install dependencies:
``` 
npm install 
```
3. Build the script
```
npm run build
```
Script will be saved at the path dist/agent.js <br>

**— Build APK**
1. Download Fall Guys Latest APK
2. Add permission to AndroidManifest.xml
```
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
```
3. Download frida-gadget 16.7.19 for [arm](https://github.com/frida/frida/releases/download/16.7.19/frida-gadget-16.7.19-android-arm.so.xz) and [arm64](https://github.com/frida/frida/releases/download/16.7.19/frida-gadget-16.7.19-android-arm64.so.xz)
4. Install [frida-gadget injector](https://github.com/commonuserlol/fgi) (I'm using that, but you can use any other to inject gadget)
5. Extract .so files and copy downloaded frida gadgets to C:\Users\YOURUSER\\.fgi\arm.so and C:\Users\YOURUSER\\.fgi\arm64.so (rename it to arm.so and arm64.so as well)
6. Open terminal and execute command 
###### short command:
```
fgi -i <yourpathtofallguys.apk> -t script -l ./dist/agent.js --offline-mode
```
###### full command:
```
fgi -i <yourfallguys.apk> -t script -l ./dist/agent.js -n libModMenu.so -s libModMenu.s.so --offline-mode
```
Apk will be saved at the path ./yourfallguys.patched.apk 

## 🤝 Contribution
Pull requests are welcome. Got ideas or questions? Join our [Discord!](https://discord.gg/cNFJ73P6p3) <br>
Short instruction to contribute: 
1. Follow the instructions in [🏗️ Build](#%EF%B8%8F-build) up to the step with injecting frida-gadget
2. Use frida-server (if you have root) or run this command to inject frida-gadget in your apk in listen mode:
```
fgi -i <yourfallguys.apk> --offline-mode
```
3. Install and launch the apk, then inject the script (this command works only if you have frida-gadget, use other if you use frida-server):
```
npm run spawn
```

## 🙏 Special Thanks
Obed Guys Team - Some features powered by Obed Guys Team <br>
[FloyzI](https://github.com/FloyzI) - For how the game works, help with some features, localization<br>
[commonuserlol](https://github.com/commonuserlol) - For help with code and [menu](https://github.com/commonuserlol/frida-java-menu) <br>
[Dynasty-Dev](https://github.com/Dynasty-Dev) - For testing and contribution <br>
[igamegod](https://github.com/igamegod) - For help with some features
