import { AssemblyHelper } from "../../core/AssemblyHelper";

import { Logger } from "../../logger/Logger";

export class AntiAFK {
    static init(): void {
        // Classes
        const AFKManager = AssemblyHelper.MTFGClient.class("FGClient.AFKManager");

        // Methods
        AFKManager.method<void>("Start").implementation = this.startHook;

        Logger.info("[AntiAFK::init] Initialized");
    }

    private static startHook(): void {
        Logger.hook("AFKManager::Start called");
        return;
    }
}
