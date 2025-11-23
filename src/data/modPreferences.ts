export const ModPreferences = {
    VERSION: "2.58", // Don't forget update after changes!
    ENV: "release", // dev, staging, release
    FOR_GAME_VERSION: "21.0.1"
};

/*
!! TODO: 
refactor localization
logcat logging
on screen logging
unity logging
made localization for other languages (i18n)
wrapper for Il2cpp.perform main
refactor vars names
refactor menu and some other things using createPopup
refer changeResolutionScale()
show_method not overloading, just inflate
 
maybe:
refactor structure of project / script (all script in one file :cry:)
fork menu and update it to frida 17
*/

/*
                ShowAntiCheatPopup will called by _CheckRestrictedGameAccess_d__69::MoveNext corutine
                CheckRestrictedGameAccess called by OnLoginSuccessful (When you login in)
                */
