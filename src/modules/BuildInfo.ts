import { AssemblyHelper } from "../core/AssemblyHelper";
import { I18n } from "../i18n/I18n";
import { Logger } from "../logger/Logger";
import { MenuUtils } from "../ui/menu/MenuUtils";

export class BuildInfo {
    private static gameVersion: string;
    private static buildNumber: string;
    private static buildDate: string;

    static init(): void {
        const BuildInfo = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.BuildInfo");

        // @ts-ignore
        BuildInfo.method<void>("OnEnable").implementation = this.onEnableHook;

        Logger.info("[BuildInfo::init] Initialized");
    }

    private static onEnableHook(this: Il2Cpp.Object): void {
        Logger.hook("BuildInfo::OnEnable called");
        BuildInfo.gameVersion = Il2Cpp.application.version!;
        BuildInfo.buildNumber = this.field<Il2Cpp.String>("buildNumber").value.content!;
        BuildInfo.buildDate = this.field<Il2Cpp.String>("buildDate").value.content!;

        MenuUtils.addCenterText(BuildInfo.getShortString());

        return this.method<void>("OnEnable").invoke();
    }

    private static getShortString(): string {
        return I18n.t("menu.other.based_on", `${this.gameVersion} / #${this.buildNumber} / ${this.buildDate}`);
    }
}
