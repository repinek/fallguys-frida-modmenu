import "frida-il2cpp-bridge";

import { AssemblyHelper } from "./core/AssemblyHelper";

import { ModPreferences } from "./data/ModPreferences";

import { I18n } from "./i18n/I18n";

import { Logger } from "./logger/Logger";
import { UnityLogger } from "./logger/UnityLogger";

import { PopupManager } from "./ui/popup/PopupManager";
import { MenuBuilder } from "./ui/menu/MenuBuilder";

import { LocalisedStrings } from "./utils/game/LocalisedStrings";
import { UnityUtils } from "./utils/UnityUtils";
import { UpdateUtils } from "./utils/UpdateUtils";
import { BanBypass } from "./modules/BanBypass";
import { BuildInfo } from "./modules/BuildInfo";
import { Catapult } from "./modules/Catapult";
import { MatchInfo } from "./modules/MatchInfo";
import { FGDebug } from "./modules/FGDebug";
import { GraphicsManager } from "./modules/GraphicsManager";
import { Network } from "./modules/Network";
import { UICanvas } from "./modules/UICanvas";
import { UwUify } from "./modules/UwUify";
import { AntiAFK } from "./modules/player/AntiAFK";
import { CharacterPhysics } from "./modules/player/CharacterPhysics";
import { TeleportManager } from "./modules/player/TeleportManager";
import { DoorManager } from "./modules/rounds/DoorManager";
import { PerfectMatchManager } from "./modules/rounds/PerfectMatchManager";
import { TipToeManager } from "./modules/rounds/TipToeManager";

function initEngine(): void {
    AssemblyHelper.init();
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
    UpdateUtils.checkGameVersion();
    UpdateUtils.checkForUpdate();
}

function init(): void {
    Logger.debug("Script Loaded");
    Il2Cpp.perform(() => {
        Logger.debug("IL2CPP Loaded");
        Logger.infoGreen(`Fall Guys Frida Mod Menu ${ModPreferences.VERSION} (${ModPreferences.ENV}), Game Version: ${Il2Cpp.application.version!}`);

        initEngine();

        initMod();

        // Init Unity related
        UnityLogger.init();
        UnityUtils.init();
        LocalisedStrings.init();
    }).catch(error => Logger.error(`Failed to initialize script: ${error}`));
}

init();
