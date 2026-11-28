import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { Logger } from "../../../utils/Logger";
import { ModSettings } from "../../data/ModSettings";
import { I18n } from "../../i18n/I18n";

export class MatchmakingInfo {
    static init(): void {
        const FNMMSClientRemoteService = AssemblyHelper.MTFGClient.class("FGClient.FNMMSClientRemoteService");

        // @ts-ignore
        FNMMSClientRemoteService.method<void>("ProcessMessageReceived").implementation = this.processMessageReceivedHook;

        Logger.info("[Network::init] Initialized");
    }

    private static processMessageReceivedHook(this: Il2Cpp.Object, jsonMessage: Il2Cpp.String): void {
        this.method<void>("ProcessMessageReceived", 1).invoke(jsonMessage);
        if (!ModSettings.showQueuedPlayers) return;

        const content = jsonMessage.content;
        if (!content) return;
        Logger.debug(`[Network::processMessageReceivedHook] Received matchmaking message: ${content}`);

        // payload example: {"payload":{"queuedPlayers":6,"state":"Queued"},"name":"StatusUpdate"}
        const payload = JSON.parse(content)?.payload;
        if (payload?.state === "Queued") {
            Logger.toast(I18n.t("network_toasts.queued_players", payload.queuedPlayers.toString()));
        }
    }
}
