import "frida-il2cpp-bridge";
import "frida-java-menu";

import { AssemblyHelper } from "./core/assemblyHelper.js";
import { ModuleManager } from "./core/moduleManager.js";

import { ModPreferences } from "./data/modPreferences.js";

import { I18n } from "./i18n/i18n.js";

import { Logger } from "./logger/logger.js";

import { MenuBuilder } from "./ui/menu.js";

import { UnityUtils } from "./utils/unityUtils.js";
import { UpdateUtils } from "./utils/updateUtils.js";

function main() {
    Logger.infoGreen(`Fall Guys Frida Mod Menu ${ModPreferences.VERSION} (${ModPreferences.ENV}), Game Version: ${Il2Cpp.application.version!}`);
    UpdateUtils.checkForUpdate();

    I18n.init();

    AssemblyHelper.init();

    UnityUtils.init();

    ModuleManager.initAll();

    MenuBuilder.init();

    // === Classes ===
    // const LobbyService = AssemblyHelper.MTFGClient.class("FGClient.CatapultServices.LobbyService");

    // === Methods ===
    // const OnMainMenuDisplayed_method = LobbyService.method("OnMainMenuDisplayed", 1);

    // === Cache ===
    // let reachedMainMenu = false;

    //Menu.toast(en.messages.menu_will_appear_later, 1);

    // === Hooks ===
    // OnMainMenuDisplayed_method.implementation = function (event) {
    //     Logger.hook("OnMainMenuDisplayed Called");

    //     if (!reachedMainMenu) {
    //         /*
    //         sooo, if you load all these assemblies before the menu appears, the game will freeze when entering the main menu.
    //         probably, shitcode from menu is a reason, idk.

    //         you can load the menu here, in this function, and it will wait another 2 seconds in the initMenu function before showing it (bad, but working (not always)),
    //         */
    //         Menu.toast(en.messages.display_menu, 0);

    //         Menu.waitForInit(initMenu);
    //         reachedMainMenu = true;
    //     }

    //     return this.method("OnMainMenuDisplayed", 1).invoke(event);
    // };
}

Il2Cpp.perform(main);
