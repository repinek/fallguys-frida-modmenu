> [!WARNING]  
> This project is for educational purposes only.  
> The author is not responsible for any bans from the use of this tool.  
> Use it at your own risk.
> Works on my machine.

# Fall Guys Mod Menu
Android Fall Guys cheat using [Frida](https://frida.re/) and [frida-il2cpp-bridge](https://github.com/vfsfitvnm/frida-il2cpp-bridge)

## Screenshots
![Demo](https://github.com/user-attachments/assets/57b9a4cd-3a62-47b7-8a3e-17dc801ea0b3)

<img src="https://github.com/user-attachments/assets/59ddff53-6dc1-49cc-8396-4243bb3c096a" width="500" height="224"/>
<img src="https://github.com/user-attachments/assets/f2164534-1700-4ba6-b681-576dca29583d" width="500" height="224"/>

## Message To MediaTonic 
Please, Fix the game. You've had over a year to fix the many bugs and the bad optimization on consoles (Switch, Xbox, PS) makes it unplayable. It's time to focus on the state of the game. 

## Features  
- Bypass character physics checks 
- Change speed 
- Change velocity / No velocity / Negative velocity 
- 360 Dives 
- Teleport To Finish (Only Races)
- Remove FPS Limit 
- Display FGDebug (Minimum, maximum, average and current FPS, Time, Ping, Dropped packets)

## Build 
**— Build script**
1. Clone the repository:
```
git clone https://github.com/repinek/FallGuysFridaModMenu
cd FallGuysFridaModMenu
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
On startup it will ask for permission to display over other apps, if it doesn't ask for it - grant it yourself <br>
**HyperOS**, **ColorOS**, **OneUI**, **HarmonyOS** and other **OEM ROMs** may not work properly or not at all <br>
**Please, prefer roms with non/slightly modified ART code (AOSP forks mainly)**

## Special Thanks
[FloyzI](https://github.com/FloyzI) - for how the game works <br>
[commonuserlol](https://github.com/commonuserlol) - for help with code and [menu](https://github.com/commonuserlol/frida-java-menu)
