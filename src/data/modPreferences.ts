export const ModPreferences = {
    VERSION: "2.81", // Don't forget update after changes!
    ENV: "release", // dev, staging, release
    FOR_GAME_VERSION: "21.0.1"
};

/*
!! TODO: 
createmenu only when get build info (and fgdebug)
implement uwuify
implement extensions.ts (.setActive, .getGameObject) 
i18n refactor
logging refactor
project structure
rename onEnable to initHooks
add changelog in menu
create cool screenshots for readme
improve logging at modules
logcat logging
on screen logging
unity logging
made localization for other languages (i18n)
refer changeResolutionScale()
custom image on loading screen
login by token
config file (?)
log file
all cosmetics lobby (?)
comments over module
separate configs
check old commits for pre-installed value on seekbars

maybe:
fork menu and update it to frida 17

DONE:
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
