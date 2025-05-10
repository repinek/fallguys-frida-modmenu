> [!WARNING]  
> This project is for educational purposes only.  
> The author is not responsible for any bans from the use of this tool!  
> Use it at your own risk.

# Fall Guys Mod Menu
Android Fall Guys mod menu using [Frida](https://frida.re/) and [frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge) <br>

[Cheating Discord Server](https://discord.gg/cNFJ73P6p3)

## Screenshots
![Demo](https://github.com/user-attachments/assets/57b9a4cd-3a62-47b7-8a3e-17dc801ea0b3)

<img src="https://github.com/user-attachments/assets/59ddff53-6dc1-49cc-8396-4243bb3c096a" width="500" height="224"/>
<img src="https://github.com/user-attachments/assets/f2164534-1700-4ba6-b681-576dca29583d" width="500" height="224"/>

## Features 

### Movement
- 360 Dives
- Air Jump
- Change Speed
- Change Vertical Velocity / No Velocity / Negative Velocity
- Change Jump and Dive Strength

### Rounds helper
- Hide Real Doors (Door Dash and Lost Temple)
- Hide Fake Platforms (Tip Toe)

### Teleports
- Teleport To Finish or Crown
- Teleport To Random Player
- Teleport To Bubble, Active Button or Score Zone

### Other
- Change FOV
- Display FGDebug
  - Shows FPS (min/max/avg/current), Time, Ping, Dropped Packets
- Change Resolution
- Show Number of Queued Players
- Show Game Details
  - Shows RoundID, seed Initial Players, Eliminated Players
- Show Server Details
  - Shows Server IP, Host, Ping, LAG


### Features that always work (cannot be disabled)
- Bypass Character Physics Checks
- Remove FPS Limit
- Anti-AFK
  
## Installation
Just download and install the .apk from [Releases](https://github.com/repinek/fallguys-frida-modmenu/releases/latest)
> If you don't want to wait for game resources to download, copy the .obb file from: <br>
> Android/obb/com.Mediatonic.FallGuys_client/ to <br>
> Android/obb/com.Mediatonic.FallGuys_client.modmenu/, then rename it by adding .modmenu before .obb <br>
> Final file name example: main.XXXX.com.mediatonic.FallGuys_client.modmenu.obb <br>

## Build 
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
Script will be saved at the path dist/agent.js <br> <br>
**— Build APK <br>**
1. Download FallGuys Latest APK
2. Add permission to AndroidManifest.xml
```
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
```
3. Inject frida-gadget. I'm using [that](https://github.com/commonuserlol/fgi)
```
fgi -i <yourfallguys.apk> -t script -l ./dist/agent.js
```
Apk will be saved at the path ./yourfallguys.patched.apk 

## Troubleshooting  
> This project is created only for educational and entertainment purposes. I won't be providing support.

In The Main Menu it will ask for permission to display over other apps, If it doesn’t ask for it, grant it manually. <br><br>
**HyperOS, ColorOS, OneUI, HarmonyOS**, and other OEM ROMs may not work properly or at all. <br>
**It is recommended to use ROMs with minimal changes to ART (mainly AOSP forks).** <br>
**EMULATORS ARE NOT SUPPORTED!!** <br>

## Special Thanks
Obed Guys Team - Some features powered by Obed Guys Team <br>
[FloyzI](https://github.com/FloyzI) - for how the game works <br>
[commonuserlol](https://github.com/commonuserlol) - for help with code and [menu](https://github.com/commonuserlol/frida-java-menu) <br>
[Dynasty-Dev](https://github.com/Dynasty-Dev) - for testing
[igamegod](https://github.com/igamegod) - for help with some functions
