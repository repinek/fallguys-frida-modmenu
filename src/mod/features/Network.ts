import { AssemblyHelper } from "../../engine/AssemblyHelper";
import { Logger } from "../../utils/Logger";
import { ModSettings } from "../data/ModSettings";
import { I18n } from "../i18n/I18n";

export class Network {
    static init(): void {
        // Classes
        const AnalyticsService = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Analytics.AnalyticsService");
        const FNMMSClientRemoteService = AssemblyHelper.MTFGClient.class("FGClient.FNMMSClientRemoteService");

        // Methods
        //@ts-ignore
        AnalyticsService.method<void>("SendEventBatch").implementation = this.sendEventBatchHook;
        //@ts-ignore
        FNMMSClientRemoteService.method<void>("ProcessMessageReceived").implementation = this.processMessageReceivedHook;

        Logger.info("[Network::init] Initialized");
    }

    private static sendEventBatchHook(this: Il2Cpp.Object): void {
        if (ModSettings.disableAnalytics) {
            return;
        }
        return this.method<void>("SendEventBatch").invoke();
    }

    private static processMessageReceivedHook(this: Il2Cpp.Object, jsonMessage: Il2Cpp.String): void {
        if (ModSettings.showQueuedPlayers) {
            const json = JSON.parse(jsonMessage.content!); // .content because it's Il2cpp.String
            Logger.debug(`[${Network.name}] Received matchmaking message: ${jsonMessage.content!}`);

            // payload example: {"payload":{"queuedPlayers":6,"state":"Queued"},"name":"StatusUpdate"}
            if (json.payload.state === "Queued") {
                Logger.toast(I18n.t("network_toasts.queued_players", json.payload.queuedPlayers.toString()));
            }
        }
        return this.method<void>("ProcessMessageReceived", 1).invoke(jsonMessage);
    }
}
