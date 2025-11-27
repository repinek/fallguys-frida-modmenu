import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { Logger } from "../../logger/logger.js";
import { UnityUtils } from "../../utils/unityUtils.js";
import { I18n } from "../../i18n/i18n.js";
import * as JavaUtils from "../../utils/javaUtils.js";

export class MatchInfoModule extends BaseModule {
    public name = "MatchInfo";

    private GlobalGameStateClient!: Il2Cpp.Class;
    private ClientGameManager!: Il2Cpp.Class;

    public init(): void {
        this.GlobalGameStateClient = AssemblyHelper.MTFGClient.class("FGClient.GlobalGameStateClient");
        this.ClientGameManager = AssemblyHelper.MTFGClient.class("FGClient.ClientGameManager");
    }

    public showServerDetails(): void {
        try {
            const gameState = UnityUtils.getInstance(this.GlobalGameStateClient);

            if (!gameState) {
                Logger.debug(`[${this.name}::showServerDetails] Not in the game`);
                //menu.toast
                return;
            }

            const networkManager = gameState.method<Il2Cpp.Object>("get_NetworkManager").invoke();
            const gameConnection = networkManager.method<Il2Cpp.Object>("get_ConnectionToServer").invoke();

            const hostIPAddr = networkManager.method<Il2Cpp.String>("get_HostIPAddr").invoke().content;
            const hostPortNo = networkManager.method<number>("get_HostPortNo").invoke();
            const rtt = gameConnection.method<number>("CurrentRtt").invoke();

            const infoString = `Server: ${hostIPAddr}:${hostPortNo}\nPing: ${rtt}ms`;

            // Menu.Toast(infoString, 0);
            JavaUtils.copyToClipboard(`${hostIPAddr}:${hostPortNo}`);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    public showGameDetails(): void {
        try {
            const gameManager = UnityUtils.getInstance(this.ClientGameManager);

            if (!gameManager) {
                Logger.debug(`[${this.name}::showGameDetails] Not in the game`);
                return;
            }

            const round = gameManager.field<Il2Cpp.Object>("_round").value;
            const roundID = round.method<Il2Cpp.String>("get_Id").invoke().content;
            const seed = gameManager.method<number>("get_RandomSeed").invoke();
            const eliminatedCount = gameManager.field<number>("_eliminatedPlayerCount").value;

            //Menu.toast(`RoundID: ${roundID}\nSeed: ${seed}\nEliminated: ${eliminatedCount}`, 1);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }
}
