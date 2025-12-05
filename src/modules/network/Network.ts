import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { ModSettings } from "../../data/ModSettings";
import { I18n } from "../../i18n/I18n";
import { Logger } from "../../logger/Logger";

export class NetworkModule extends BaseModule {
    public readonly name = "Network";

    // Classes
    private AnalyticsService!: Il2Cpp.Class;
    private FNMMSClientRemoteService!: Il2Cpp.Class;

    // Methods
    private SendEventBatch!: Il2Cpp.Method;
    private ProcessMessageReceived!: Il2Cpp.Method;

    public init(): void {
        this.AnalyticsService = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Analytics.AnalyticsService");
        this.FNMMSClientRemoteService = AssemblyHelper.MTFGClient.class("FGClient.FNMMSClientRemoteService");

        this.SendEventBatch = this.AnalyticsService.method<void>("SendEventBatch");
        this.ProcessMessageReceived = this.FNMMSClientRemoteService.method<void>("ProcessMessageReceived");
    }

    public override initHooks(): void {
        const module = this;

        this.SendEventBatch.implementation = function (): void {
            if (ModSettings.disableAnalytics) {
                return;
            }
            return this.method<void>("SendEventBatch").invoke();
        };

        //@ts-ignore
        this.ProcessMessageReceived.implementation = function (jsonMessage: Il2Cpp.String): void {
            if (ModSettings.showQueuedPlayers) {
                const json = JSON.parse(jsonMessage.content!); // .content because it's Il2cpp.String
                Logger.debug(`[${module.name}] Received matchmaking message: ${jsonMessage.content!}`);

                // payload example: {"payload":{"queuedPlayers":6,"state":"Queued"},"name":"StatusUpdate"}
                if (json.payload.state == "Queued") {
                    Logger.toast(I18n.t("network_toasts.queued_players", json.payload.queuedPlayers.toString()));
                }
            }
            return this.method<void>("ProcessMessageReceived", 1).invoke(jsonMessage);
        };
    }
}
