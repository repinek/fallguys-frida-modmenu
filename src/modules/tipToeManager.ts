import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { I18n } from "../i18n/i18n.js";
import { UnityUtils } from "../utils/unityUtils.js";

export class TipToeModule extends BaseModule {
    public name = "TipToe Manager";

    // Classes
    private TipToe_Platform!: Il2Cpp.Class;

    public init(): void {
        this.TipToe_Platform = AssemblyHelper.TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");
    }

    public removeFakeTipToe(): void {
        const platforms = UnityUtils.findObjectsOfTypeAll(this.TipToe_Platform);

        if (platforms.length === 0) {
            Menu.toast(`[${this.name}] ${I18n.t("toasts.no_tiptoe")}`, 0);
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
