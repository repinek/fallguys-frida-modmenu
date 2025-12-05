declare const process: { env: { BUILD_ENV: string } };

export const ModPreferences = {
    VERSION: "2.122", // Don't forget update after changes!
    ENV: (process.env.BUILD_ENV || "dev") as "dev" | "staging" | "release",
    FOR_GAME_VERSION: "21.1.1"
} as const;

/*
!! TODO: 
fix spam popups
minimalistic fps counter
eula popup (cool)
project structure in readme
create cool screenshots for readme
improve logging at modules
on screen logging
made localization for other languages
refer changeResolutionScale()
custom image on loading screen
login by token
config file (?)
log file
all cosmetics lobby (?)
check old commits for pre-installed value on seekbars

maybe:
fork menu and update it to frida 17

DONE:
[x] add changing platform & some other things
[x] PascalCase naming
[x] remove .js from imports since we using webpack
[x] move menu in differents files
[x] separate configs
[x] change language
[x] move popup manager to ui 
[x] update to 21.1.1
[x] describe functions in javaUtils
[x] fgdebug fix [ERROR]  il2cpp: cannot get element at index 0 as the array length is 0
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
[x] wrapper over setActive
[x] refactor localization (info and other)
[x] wrapper for Il2cpp.perform main
[x] refactor vars names
[x] refactor menu and some other things using createPopup
[x] refactor structure of project / script (all script in one file :cry:) 

will not be done: 
implement extensions.ts (.setActive, .getGameObject) 
*/
