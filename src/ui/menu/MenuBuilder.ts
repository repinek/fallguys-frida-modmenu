import Java from "frida-java-bridge";

import { Constants } from "../../data/Constants";
import { ObsidianConfig } from "../../data/LayoutConfig";
import { ModPreferences } from "../../data/ModPreferences";

import { I18n } from "../../i18n/I18n";

import { Logger } from "../../logger/Logger";

import { MenuTabs } from "./MenuTabs";
import { MenuUtils } from "./MenuUtils";
import { Composer, ObsidianLayout, waitForInit } from "frida-java-menu";

export class MenuBuilder {
    private static readonly tag = "MenuBuilder";

    static layout: ObsidianLayout;

    static init(): void {
        if (Java.available) {
            Java.perform(() => {
                waitForInit(MenuBuilder.build);
            });
            Logger.info(`[${this.tag}::init] Initialized`);
        }
    }

    private static build(): void {
        MenuBuilder.layout = new ObsidianLayout(ObsidianConfig);

        const title = I18n.t("menu.info.title");
        const desc = I18n.t("menu.info.desc", ModPreferences.VERSION, ModPreferences.ENV);

        const composer = new Composer(title, desc, MenuBuilder.layout);
        composer.icon(Constants.MOD_MENU_ICON_URL, "Web");

        MenuUtils.getModules();
        MenuTabs.buildAll(MenuBuilder.layout);

        composer.show();
    }
}
