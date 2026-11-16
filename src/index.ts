import "frida-il2cpp-bridge";

import { AssemblyHelper } from "./engine/AssemblyHelper";
import { UnityLogger } from "./engine/UnityLogger";
import { LocalisedStringsHook } from "./fallguys/LocalisedStringsHook";
import { PopupManager } from "./fallguys/wrappers/ui/PopupManager";
import { Constants } from "./mod/data/Constants";
import { ModPreferences } from "./mod/data/ModPreferences";
import { BanBypass } from "./mod/features/BanBypass";
import { BuildInfo } from "./mod/features/BuildInfo";
import { Catapult } from "./mod/features/Catapult";
import { FGDebug } from "./mod/features/FGDebug";
import { GraphicsManager } from "./mod/features/GraphicsManager";
import { MatchInfo } from "./mod/features/MatchInfo";
import { Network } from "./mod/features/Network";
import { AntiAFK } from "./mod/features/player/AntiAFK";
import { CharacterPhysics } from "./mod/features/player/CharacterPhysics";
import { TeleportManager } from "./mod/features/player/TeleportManager";
import { DoorManager } from "./mod/features/rounds/DoorManager";
import { PerfectMatchManager } from "./mod/features/rounds/PerfectMatchManager";
import { TipToeManager } from "./mod/features/rounds/TipToeManager";
import { UICanvas } from "./mod/features/UICanvas";
import { UpdateChecker } from "./mod/features/UpdateChecker";
import { UwUify } from "./mod/features/UwUify";
import { I18n } from "./mod/i18n/I18n";
import { MenuBuilder } from "./mod/ui/MenuBuilder";
import { Logger } from "./utils/Logger";

function initEngine(): void {
    AssemblyHelper.init();

    UnityLogger.init(Constants.UNITY_LOGGING);
}

function initMod(): void {
    I18n.init();

    // Init features
    // Player
    AntiAFK.init();
    CharacterPhysics.init();
    TeleportManager.init();

    // Rounds
    DoorManager.init();
    PerfectMatchManager.init();
    TipToeManager.init();

    // Other
    BanBypass.init();
    BuildInfo.init();
    Catapult.init();
    FGDebug.init();
    GraphicsManager.init();
    MatchInfo.init();
    Network.init();
    UICanvas.init();
    UwUify.init();

    // Init UI
    PopupManager.init();
    MenuBuilder.init();

    // Init updater
    UpdateChecker.checkGameVersion();
    UpdateChecker.checkForUpdate();
}

function initGame(): void {
    LocalisedStringsHook.init();
}

function init(): void {
    Logger.debug("Script Loaded");

    Il2Cpp.perform(() => {
        Logger.debug("IL2CPP Loaded");
        Logger.infoGreen(`Fall Guys Frida Mod Menu ${ModPreferences.VERSION} (${ModPreferences.ENV}), Game Version: ${Il2Cpp.application.version!}`);

        initEngine();
        initMod();
        initGame();
    }).catch(error => Logger.error(`Failed to initialize script: ${error}`));
}

init();
