import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { I18n } from "../../i18n/I18n";
import { Logger } from "../../logger/Logger";
import { MenuUtils } from "../../ui/menu/MenuUtils";

export class BuildInfoModule extends BaseModule {
    public readonly name = "BuildInfo";

    // Classes
    private BuildInfo!: Il2Cpp.Class;

    // Methods
    private BuildInfoOnEnable!: Il2Cpp.Method;

    private gameVersion!: string;
    private buildNumber!: string;
    private buildDate!: string;

    public init(): void {
        this.BuildInfo = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.BuildInfo");

        this.BuildInfoOnEnable = this.BuildInfo.method<void>("OnEnable");
    }

    public override initHooks(): void {
        const module = this;

        this.BuildInfoOnEnable.implementation = function (): void {
            Logger.hook("BuildInfo::OnEnable called");
            module.gameVersion = Il2Cpp.application.version!;
            module.buildNumber = this.field<Il2Cpp.String>("buildNumber").value.content!;
            module.buildDate = this.field<Il2Cpp.String>("buildDate").value.content!;

            MenuUtils.addCenterText(module.getShortString());

            return this.method<void>("OnEnable").invoke();
        };
    }

    private getShortString(): string {
        return I18n.t("menu.other.based_on", `${this.gameVersion} / #${this.buildNumber} / ${this.buildDate}`);
    }
}
