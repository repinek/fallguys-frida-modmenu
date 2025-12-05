import "frida-il2cpp-bridge";
import "frida-java-menu";

import { AssemblyHelper } from "./core/AssemblyHelper";
import { ModuleManager } from "./core/ModuleManager";

import { ModPreferences } from "./data/ModPreferences";

import { I18n } from "./i18n/I18n";

import { Logger } from "./logger/Logger";
import { UnityLogger } from "./logger/UnityLogger";

import { PopupManager } from "./ui/popup/PopupManager";
import { MenuBuilder } from "./ui/menu/MenuBuilder";

import { LocalisedStrings } from "./utils/game/LocalisedStrings";
import { UnityUtils } from "./utils/UnityUtils";
import { UpdateUtils } from "./utils/UpdateUtils";

class FallGuysFridaModMenu {
    static init() {
        try {
            Logger.debug("Script Loaded");
            Il2Cpp.perform(() => {
                Logger.debug("IL2CPP Loaded");
                Logger.infoGreen(`Fall Guys Frida Mod Menu ${ModPreferences.VERSION} (${ModPreferences.ENV}), Game Version: ${Il2Cpp.application.version!}`);
                I18n.init();

                // Init Unity related
                AssemblyHelper.init();
                UnityLogger.init();
                UnityUtils.init();
                ModuleManager.initAll();
                LocalisedStrings.init();

                // Init UI
                PopupManager.init();
                MenuBuilder.init();

                UpdateUtils.checkForUpdate();
            });
        } catch (error: any) {
            // TODO: log file
            Logger.toast(`Error while loading script: ${error.message}`, 1);
        }
    }
}

FallGuysFridaModMenu.init();
