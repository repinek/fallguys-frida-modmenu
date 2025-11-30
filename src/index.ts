import "frida-il2cpp-bridge";
import "frida-java-menu";

import { AssemblyHelper } from "./core/assemblyHelper.js";
import { ModuleManager } from "./core/moduleManager.js";

import { ModPreferences } from "./data/modPreferences.js";

import { I18n } from "./i18n/i18n.js";

import { Logger } from "./logger/logger.js";
import { UnityLogger } from "./logger/unityLogger.js";

import { MenuBuilder } from "./ui/menu.js";

import { CMSLoader } from "./utils/game/CMSLoader.js";
import { UnityUtils } from "./utils/unityUtils.js";
import { UpdateUtils } from "./utils/updateUtils.js";

// This project is litterally fking race condition i'm crying
class FallGuysFridaModMenu {
    static init() {
        try {
            Il2Cpp.perform(() => {
                Logger.infoGreen(`Fall Guys Frida Mod Menu ${ModPreferences.VERSION} (${ModPreferences.ENV}), Game Version: ${Il2Cpp.application.version!}`);
                I18n.init();

                // add EnvironmentManager or smth like that for loading this easily (or no??)
                AssemblyHelper.init();
                UnityLogger.init();
                UnityUtils.init();
                ModuleManager.initAll();
                CMSLoader.init();
                // Only after all that we can do your things
                
                MenuBuilder.init();

                UpdateUtils.checkForUpdate();
            });
        } catch (error: any) {
            //
        }
    }
}

FallGuysFridaModMenu.init();
