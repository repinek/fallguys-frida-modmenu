import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { GameObject } from "../../../engine/wrappers/GameObject";
import { Resources } from "../../../engine/wrappers/Resources";
import { Logger } from "../../../utils/Logger";
import { I18n } from "../../i18n/I18n";

/*
 * Every TipToe tile has Levels::TipToe::TipToe_Platform component
 * It has a boolean field IsFakePlatform
 * If it returns true, we disable the GameObject using SetActive
 */

export class TipToeManager {
    // Classes
    private static TipToe_Platform: Il2Cpp.Class;

    static init(): void {
        this.TipToe_Platform = AssemblyHelper.TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");

        Logger.info("[TipToeManager::init] Initialized");
    }

    static removeFakeTipToe(): void {
        const platforms = Resources.findObjectsOfTypeAll(this.TipToe_Platform.type.object);

        if (platforms.length === 0) {
            Logger.debug(`[${this.name}::removeFakeTipToe] No TipToe`);
            Logger.toast(I18n.t("rounds_toasts.no_tiptoe"), 0);
            return;
        }

        for (const tiptoe of platforms) {
            const isFake = tiptoe.method<boolean>("get_IsFakePlatform").invoke();

            if (isFake) {
                const tiptoeObject = tiptoe.method<Il2Cpp.Object>("get_gameObject").invoke();
                GameObject.setActive(tiptoeObject, false);
            }
        }
    }
}
