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
import { UwUify } from "./mod/features/UwUify";
import { I18n } from "./mod/i18n/I18n";
import { MenuBuilder } from "./mod/ui/MenuBuilder";
import { UpdateChecker } from "./mod/utils/UpdateChecker";
import { Logger } from "./utils/Logger";

function logBanner(): void {
    const { VERSION, ENV, FOR_GAME_VERSION } = ModPreferences;
    const gameVersion = Il2Cpp.application.version!;

    Logger.infoGreen(`Fall Guys Frida Mod Menu ${VERSION} (${ENV}), Game Version: ${gameVersion}`);

    if (gameVersion !== ModPreferences.FOR_GAME_VERSION) {
        Logger.warn(`[UpdateChecker::checkGameVersion] Game version ${gameVersion} is not supported. Expected ${FOR_GAME_VERSION}. Things may break`);
    }
}

function initEngine(): void {
    AssemblyHelper.init();

    UnityLogger.init(Constants.UNITY_LOGGING);
}

function initGame(): void {
    PopupManager.init();
    LocalisedStringsHook.init();
}

function initMod(): void {
    I18n.init();
    UpdateChecker.fetchLatestVersion();

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
    MenuBuilder.init();
}

function init(): void {
    Logger.debug("Script Loaded");

    Il2Cpp.perform(() => {
        Logger.debug("IL2CPP Loaded");
        logBanner();

        initEngine();
        initGame();
        initMod();
    }).catch(error => Logger.error(`Failed to initialize script: ${error}`));
}

init();
