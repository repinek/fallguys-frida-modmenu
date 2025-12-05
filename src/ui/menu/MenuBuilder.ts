import { Constants } from "../../data/constants.js";
import { ObsidianConfig } from "../../data/layoutConfig.js";
import { ModPreferences } from "../../data/modPreferences.js";

import { I18n } from "../../i18n/i18n.js";

import { Logger } from "../../logger/logger.js";

import { MenuTabs } from "./MenuTabs.js";
import { MenuUtils } from "./MenuUtils.js";

export class MenuBuilder {
    private static readonly tag = "MenuBuilder";

    static layout: Menu.ObsidianLayout;

    static init(): void {
        if (Java.available) {
            Java.perform(() => {
                Menu.waitForInit(MenuBuilder.build);
            });
            Logger.info(`[${this.tag}::init] Initialized`);
        }
    }

    private static build(): void {
        MenuBuilder.layout = new Menu.ObsidianLayout(ObsidianConfig);

        const title = I18n.t("menu.info.title");
        const desc = I18n.t("menu.info.desc", ModPreferences.VERSION, ModPreferences.ENV);

        const composer = new Menu.Composer(title, desc, MenuBuilder.layout);
        composer.icon(Constants.MOD_MENU_ICON_URL, "Web");

        MenuUtils.getModules();
        MenuTabs.buildAll(MenuBuilder.layout);

        composer.show();
    }
}
