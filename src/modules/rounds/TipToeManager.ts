import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { I18n } from "../../i18n/I18n";
import { UnityUtils } from "../../utils/UnityUtils";
import { Logger } from "../../logger/Logger";

/*
 * Every TipToe tile has Levels::TipToe::TipToe_Platform component
 * It has a boolean field IsFakePlatform
 * If it returns true, we disable the GameObject using SetActive
 */

export class TipToeManagerModule extends BaseModule {
    public readonly name = "TipToeManager";

    // Classes
    private TipToe_Platform!: Il2Cpp.Class;

    public init(): void {
        this.TipToe_Platform = AssemblyHelper.TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");
    }

    public removeFakeTipToe(): void {
        const platforms = UnityUtils.FindObjectsOfTypeAll(this.TipToe_Platform);

        if (platforms.length === 0) {
            Logger.debug(`[${this.name}::removeFakeTipToe] No TipToe`);
            Logger.toast(I18n.t("rounds_toasts.no_tiptoe"), 0);
            return;
        }

        for (const tiptoe of platforms) {
            const isFake = tiptoe.method<boolean>("get_IsFakePlatform").invoke();

            if (isFake) {
                const tiptoeObject = tiptoe.method<Il2Cpp.Object>("get_gameObject").invoke();
                UnityUtils.SetActive(tiptoeObject, false);
            }
        }
    }
}
