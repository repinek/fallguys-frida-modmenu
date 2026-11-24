import { AndroidUtils } from "../../android/AndroidUtils";
import { AssemblyHelper } from "../../engine/AssemblyHelper";
import { UnityUtils } from "../../engine/UnityUtils";
import { Logger } from "../../utils/Logger";
import { I18n } from "../i18n/I18n";

export class MatchInfo {
    private static ClientGameManager: Il2Cpp.Class;
    private static GlobalGameStateClient: Il2Cpp.Class;

    static init(): void {
        this.ClientGameManager = AssemblyHelper.MTFGClient.class("FGClient.ClientGameManager");
        this.GlobalGameStateClient = AssemblyHelper.MTFGClient.class("FGClient.GlobalGameStateClient");

        Logger.info("[MatchInfo::init] Initialized");
    }

    static showGameDetails(): void {
        const gameStateInstance = this.getGameStateForMatch("showGameDetails");
        if (!gameStateInstance) return;
        // ClientGameStateView
        const gameStateView = gameStateInstance.method<Il2Cpp.Object>("get_GameStateView").invoke();

        // Handle out arg
        // private bool GetLiveClientGameManager(out ClientGameManager cmg) { }
        const mem = Memory.alloc(Process.pointerSize);
        const out = new Il2Cpp.Reference<Il2Cpp.Object>(mem, this.ClientGameManager.type);
        const isSuccess = gameStateView.method<boolean>("GetLiveClientGameManager").invoke(out);
        if (!isSuccess) return;

        const gameManagerInstance = out.value;
        const round = gameManagerInstance.field<Il2Cpp.Object>("_round").value;
        const roundID = round.method<Il2Cpp.String>("get_Id").invoke().content!;
        const seed = gameManagerInstance.method<number>("get_RandomSeed").invoke();
        const eliminatedCount = gameManagerInstance.field<number>("_eliminatedPlayerCount").value;

        const infoString = I18n.t("game_toasts.match_info", roundID, seed, eliminatedCount);
        Logger.toast(infoString, 1);
    }

    static showAndCopyServerDetails(): void {
        const gameStateInstance = this.getGameStateForMatch("showServerDetails");
        if (!gameStateInstance) return;

        const networkManager = gameStateInstance.method<Il2Cpp.Object>("get_NetworkManager").invoke();
        const gameConnection = networkManager.method<Il2Cpp.Object>("get_ConnectionToServer").invoke();

        const hostIPAddr = networkManager.method<Il2Cpp.String>("get_HostIPAddr").invoke().content!;
        const hostPortNo = networkManager.method<number>("get_HostPortNo").invoke();
        const rtt = gameConnection.method<number>("CurrentRtt").invoke();

        const infoString = I18n.t("game_toasts.server_info", hostIPAddr, hostPortNo, rtt);
        Logger.toast(infoString, 1);
        AndroidUtils.copyToClipboard(`${hostIPAddr}:${hostPortNo}`);
    }

    /**
     * Returns the current instance of `GlobalGameStateClient` or undefined
     * Shows a toast if the instance exists and player not in match
     */
    private static getGameStateForMatch(caller: string): Il2Cpp.Object | undefined {
        const gameStateInstance = UnityUtils.getInstance(this.GlobalGameStateClient);
        if (!gameStateInstance) return undefined;

        if (!gameStateInstance.method<boolean>("get_IsInGameplay").invoke()) {
            Logger.warn(`[MatchInfo::${caller}] Not in the game`);
            Logger.toast(I18n.t("game_toasts.not_in_match"));
            return undefined;
        }

        return gameStateInstance;
    }
}
