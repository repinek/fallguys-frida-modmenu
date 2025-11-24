import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";

import { Logger } from "../utils/logger.js";

export class AntiAFKModule extends BaseModule {
    public name = "Anti-AFK Module";

    // Classes
    private AFKManager!: Il2Cpp.Class;

    // Methods
    private AFKManagerStart!: Il2Cpp.Method;

    public init(): void {
        this.AFKManager = AssemblyHelper.MTFGClient.class("FGClient.AFKManager");

        this.AFKManagerStart = this.AFKManager.method("Start");
    }

    public override onEnable(): void {
        this.AFKManagerStart.implementation = function (): void {
            Logger.hook("AFKManager::Start called");
            return;
        };
    }
}
