import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { I18n } from "../../i18n/i18n.js";
import { Logger } from "../../logger/logger.js";
import { MenuBuilder } from "../../ui/menu.js";

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

            MenuBuilder.addCenterText(module.getShortString());

            return this.method<void>("OnEnable").invoke();
        };
    }

    private getShortString(): string {
        return I18n.t("menu.other.based_on", `${this.gameVersion} / #${this.buildNumber} / ${this.buildDate}`);
    }
}
