import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { ModSettings } from "../../data/ModSettings";

export class AnalyticsDisabler {
    static init(): void {
        const AnalyticsService = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Analytics.AnalyticsService");

        // @ts-ignore
        AnalyticsService.method<void>("SendEventBatch").implementation = this.sendEventBatchHook;
    }

    // Disable analytics patch
    private static sendEventBatchHook(this: Il2Cpp.Object): void {
        if (ModSettings.disableAnalytics) {
            return;
        }
        return this.method<void>("SendEventBatch").invoke();
    }
}
