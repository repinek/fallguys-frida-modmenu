import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { UnityUtils } from "../../utils/unityUtils.js";
import { Logger } from "../../logger/logger.js";

/*
 * Every TipToe tile has Levels::TipToe::TipToe_Platform component
 * It has a boolean field IsFakePlatform
 * If it returns true, we disable the GameObject using SetActive
 */

export class TipToeManagerModule extends BaseModule {
    public name = "TipToeManager";

    // Classes
    private TipToe_Platform!: Il2Cpp.Class;

    public init(): void {
        this.TipToe_Platform = AssemblyHelper.TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");
    }

    public removeFakeTipToe(): void {
        const platforms = UnityUtils.findObjectsOfTypeAll(this.TipToe_Platform);

        if (platforms.length === 0) {
            Logger.debug(`[${this.name}::removeFakeTipToe] No TipToe`);
            //Menu.toast(`[${this.name}] ${I18n.t("toasts.no_tiptoe")}`, 0);
            return;
        }

        for (const tiptoe of platforms) {
            const isFake = tiptoe.method<boolean>("get_IsFakePlatform").invoke();

            if (isFake) {
                const tiptoeObject = tiptoe.method<Il2Cpp.Object>("get_gameObject").invoke();
                tiptoeObject.method("SetActive").invoke(false);
            }
        }
    }
}
