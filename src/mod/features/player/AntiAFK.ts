import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { Logger } from "../../../utils/Logger";

export class AntiAFK {
    static init(): void {
        const AFKManager = AssemblyHelper.MTFGClient.class("FGClient.AFKManager");

        AFKManager.method<void>("Start").implementation = this.startHook;

        Logger.info("[AntiAFK::init] Initialized");
    }

    private static startHook(): void {
        Logger.hook("AFKManager::Start called");
        return;
    }
}
