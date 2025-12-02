import "frida-il2cpp-bridge";
import "frida-java-menu";

import { AssemblyHelper } from "./core/assemblyHelper.js";
import { ModuleManager } from "./core/moduleManager.js";

import { ModPreferences } from "./data/modPreferences.js";

import { I18n } from "./i18n/i18n.js";

import { Logger } from "./logger/logger.js";
import { UnityLogger } from "./logger/unityLogger.js";

import { PopupManager } from "./ui/popup/popupManager.js";
import { MenuBuilder } from "./ui/menu.js";

import { LocalisedStrings } from "./utils/game/localisedStrings.js";
import { UnityUtils } from "./utils/unityUtils.js";
import { UpdateUtils } from "./utils/updateUtils.js";

class FallGuysFridaModMenu {
    static init() {
        try {
            Il2Cpp.perform(() => {
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
