import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { Logger } from "../../logger/Logger";
import { UnityUtils } from "../../utils/UnityUtils";
import { I18n } from "../../i18n/I18n";
import { JavaUtils } from "../../utils/JavaUtils";

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
            const gameManagerInstance = UnityUtils.getInstance(this.ClientGameManager);

            // TODO: fix, doesn't work
            if (!gameManagerInstance) {
                Logger.debug(`[${this.name}::showGameDetails] Not in the game`);
                Logger.toast(I18n.t("game_toasts.not_in_match"));
                return;
            }

            const round = gameManagerInstance.field<Il2Cpp.Object>("_round").value;
            const roundID = round.method<Il2Cpp.String>("get_Id").invoke().content!;
            const seed = gameManagerInstance.method<number>("get_RandomSeed").invoke();
            const eliminatedCount = gameManagerInstance.field<number>("_eliminatedPlayerCount").value;

            const infoString = I18n.t("game_toasts.match_info", roundID, seed, eliminatedCount);
            Logger.toast(infoString, 1);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    public showServerDetails(): void {
        try {
            const gameStateInstance = UnityUtils.getInstance(this.GlobalGameStateClient);

            // TODO: fix, doesn't work
            if (!gameStateInstance) {
                Logger.warn(`[${this.name}::showServerDetails] Not in the game`);
                Logger.toast(I18n.t("game_toasts.not_in_match"));
                return;
            }

            const networkManager = gameStateInstance.method<Il2Cpp.Object>("get_NetworkManager").invoke();
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
