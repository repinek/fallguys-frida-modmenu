import "frida-il2cpp-bridge";
import "frida-java-menu";

import { AssemblyHelper } from "./core/assemblyHelper.js";
import { ModuleManager } from "./core/moduleManager.js";

import { ModPreferences } from "./data/modPreferences.js";

import { I18n } from "./i18n/i18n.js";

import { Logger } from "./logger/logger.js";
import { UnityLogger } from "./logger/unityLogger.js";

import { MenuBuilder } from "./ui/menu.js";

import { UnityUtils } from "./utils/unityUtils.js";
import { UpdateUtils } from "./utils/updateUtils.js";

class FallGuysFridaModMenu {
    static init() {
        Il2Cpp.perform(() => {
            Logger.infoGreen(`Fall Guys Frida Mod Menu ${ModPreferences.VERSION} (${ModPreferences.ENV}), Game Version: ${Il2Cpp.application.version!}`);
            UpdateUtils.checkForUpdate();
            I18n.init();

            AssemblyHelper.init();
            UnityLogger.init();
            UnityUtils.init();
            ModuleManager.initAll();

            MenuBuilder.init();
        });
    }
}

FallGuysFridaModMenu.init();
