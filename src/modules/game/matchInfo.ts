import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { Logger } from "../../logger/logger.js";
import { UnityUtils } from "../../utils/unityUtils.js";
import { I18n } from "../../i18n/i18n.js";
import { JavaUtils } from "../../utils/javaUtils.js";

export class MatchInfoModule extends BaseModule {
    public readonly name = "MatchInfo";

    // Classes
    private ClientGameManager!: Il2Cpp.Class;
    private GlobalGameStateClient!: Il2Cpp.Class;

    public init(): void {
        this.ClientGameManager = AssemblyHelper.MTFGClient.class("FGClient.ClientGameManager");
        this.GlobalGameStateClient = AssemblyHelper.MTFGClient.class("FGClient.GlobalGameStateClient");
    }

    public showGameDetails(): void {
        try {
            const gameManager = UnityUtils.getInstance(this.ClientGameManager);

            if (!gameManager) {
                Logger.debug(`[${this.name}::showGameDetails] Not in the game`);
                Logger.toast(I18n.t("game_toasts.not_in_match"));
                return;
            }

            const round = gameManager.field<Il2Cpp.Object>("_round").value;
            const roundID = round.method<Il2Cpp.String>("get_Id").invoke().content!;
            const seed = gameManager.method<number>("get_RandomSeed").invoke();
            const eliminatedCount = gameManager.field<number>("_eliminatedPlayerCount").value;

            const infoString = I18n.t("game_toasts.match_info", roundID, seed, eliminatedCount);
            Logger.toast(infoString, 1);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    public showServerDetails(): void {
        try {
            const gameState = UnityUtils.getInstance(this.GlobalGameStateClient);

            if (!gameState) {
                Logger.warn(`[${this.name}::showServerDetails] Not in the game`);
                Logger.toast(I18n.t("game_toasts.not_in_match"));
                return;
            }

            const networkManager = gameState.method<Il2Cpp.Object>("get_NetworkManager").invoke();
            const gameConnection = networkManager.method<Il2Cpp.Object>("get_ConnectionToServer").invoke();

            const hostIPAddr = networkManager.method<Il2Cpp.String>("get_HostIPAddr").invoke().content!;
            const hostPortNo = networkManager.method<number>("get_HostPortNo").invoke();
            const rtt = gameConnection.method<number>("CurrentRtt").invoke();

            const infoString = I18n.t("game_toasts.server_info", hostIPAddr, hostPortNo, rtt);
            Logger.toast(infoString, 1);
            JavaUtils.copyToClipboard(`${hostIPAddr}:${hostPortNo}`);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }
}
