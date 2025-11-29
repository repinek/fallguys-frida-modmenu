import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { Logger } from "../../logger/logger.js";

export class BuildInfoModule extends BaseModule {
    public name = "BuildInfo";

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

            return this.method<void>("OnEnable").invoke();
        };
    }

    public getShortString(): string {
        return `Based on: ${this.gameVersion} / #${this.buildNumber} / ${this.buildDate}`;
    }
}
