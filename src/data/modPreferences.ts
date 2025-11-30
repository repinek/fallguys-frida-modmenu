export const ModPreferences = {
    VERSION: "2.104", // Don't forget update after changes!
    ENV: "release", // dev, staging, release
    FOR_GAME_VERSION: "21.0.1"
};

/*
!! TODO: 
update to 21.1.1
describe functions in javaUtils
eula popup (cool)
fgdebug fix [ERROR]  il2cpp: cannot get element at index 0 as the array length is 0
change language
implement extensions.ts (.setActive, .getGameObject) 
project structure
add changing platform & some other things
create cool screenshots for readme
improve logging at modules
on screen logging
made localization for other languages (i18n)
refer changeResolutionScale()
custom image on loading screen
login by token
config file (?)
log file
all cosmetics lobby (?)
separate configs
check old commits for pre-installed value on seekbars

maybe:
fork menu and update it to frida 17

DONE:
[x] i18n refactor
[x] add changelog in menu
[x] build info text
[x] rename onEnable to initHooks
[x] comments over module
[x] implement uwuify
[x] logging refactor
[x] unity logging
[x] move teleportmanager from utils
[x] something with to global classes 
[x] rename velocity to gravity and dive strenght to dive force or wtf im was doing
[x] unityTools
[x] wrapper over setActive
[x] refactor localization (info and other)
[x] wrapper for Il2cpp.perform main
[x] refactor vars names
[x] refactor menu and some other things using createPopup
[x] refactor structure of project / script (all script in one file :cry:) 
*/
