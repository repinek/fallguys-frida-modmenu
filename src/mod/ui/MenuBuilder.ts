import { Composer, ObsidianLayout, waitForInit } from "frida-java-menu";

import { Logger } from "../../utils/Logger";
import { Constants } from "../data/Constants";
import { getObsidianConfig } from "../data/LayoutConfig";
import { ModPreferences } from "../data/ModPreferences";
import { I18n } from "../i18n/I18n";
import { MenuTabs } from "./MenuTabs";

export class MenuBuilder {
    private static _layout: ObsidianLayout;

    static init(): void {
        waitForInit(() => MenuBuilder.build());
        Logger.info(`[MenuBuilder::init] Initialized`);
    }

    private static build(): void {
        const layout = new ObsidianLayout(getObsidianConfig());
        this._layout = layout;

        const title = I18n.t("menu.info.title");
        const desc = I18n.t("menu.info.desc", ModPreferences.VERSION, ModPreferences.ENV);

        const composer = new Composer(title, desc, layout);
        composer.icon(Constants.MOD_MENU_ICON_URL, "Web");

        MenuTabs.buildAll(layout);

        composer.show();
    }

    static get layout(): ObsidianLayout {
        return this._layout;
    }
}
