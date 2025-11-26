import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { Config } from "../data/config.js";
import { Logger } from "../utils/logger.js";

export class NetworkModule extends BaseModule {
    public name = "Network";

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

    public override onEnable(): void {
        const module = this;

        this.SendEventBatch.implementation = function (): void {
            if (Config.Toggles.toggleDisableAnalytics) {
                return;
            }
            return this.method<void>("SendEventBatch").invoke();
        };

        //@ts-ignore
        this.ProcessMessageReceived.implementation = function (jsonMessage: Il2Cpp.String): void {
            if (Config.Toggles.toggleShowQueuedPlayers) {
                const json = JSON.parse(jsonMessage.content!); // .content because it's Il2cpp.String
                Logger.debug(`[${module.name}] Received matchmaking message: ${jsonMessage.content!}`);

                // payload example: {"payload":{"queuedPlayers":6,"state":"Queued"},"name":"StatusUpdate"}
                if (json.payload.state == "Queued") {
                    Menu.toast(`Queued Players: ${json.payload.queuedPlayers.toString()}`, 0); // TODO: add localization
                }
            }
            return this.method<void>("ProcessMessageReceived", 1).invoke(jsonMessage);
        };
    }
}
