import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";

import { Logger } from "../../logger/Logger";

export class AntiAFKModule extends BaseModule {
    public readonly name = "AntiAFK";

    // Classes
    private AFKManager!: Il2Cpp.Class;

    // Methods
    private AFKManagerStart!: Il2Cpp.Method;

    public init(): void {
        this.AFKManager = AssemblyHelper.MTFGClient.class("FGClient.AFKManager");

        this.AFKManagerStart = this.AFKManager.method<void>("Start");
    }

    public override initHooks(): void {
        this.AFKManagerStart.implementation = function (): void {
            Logger.hook("AFKManager::Start called");
            return;
        };
    }
}
