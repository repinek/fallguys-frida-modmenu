import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { Component } from "../../../engine/wrappers/Component";
import { Resources } from "../../../engine/wrappers/Resources";
import { Logger } from "../../../utils/Logger";
import { I18n } from "../../i18n/I18n";

/*
 * Every TipToe tile has Levels::TipToe::TipToe_Platform component
 * It has a boolean field IsFakePlatform
 * If it returns true, we disable the GameObject using SetActive
 */

export class TipToeReveal {
    private static TipToe_Platform: Il2Cpp.Class;

    static init(): void {
        this.TipToe_Platform = AssemblyHelper.TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");

        Logger.info("[TipToeManager::init] Initialized");
    }

    static removeFakeTipToe(): void {
        const platforms = Resources.findObjectsOfTypeAll(this.TipToe_Platform.type.object);

        if (platforms.length === 0) {
            Logger.debug(`[TipToeManager::removeFakeTipToe] No TipToe`);
            Logger.toast(I18n.t("rounds_toasts.no_tiptoe"), 0);
            return;
        }

        for (const rawTiptoe of platforms) {
            const tiptoe = new Component(rawTiptoe);
            const isFake = tiptoe.method<boolean>("get_IsFakePlatform").invoke();

            if (isFake) tiptoe.gameObject.setActive(false);
        }
    }
}
