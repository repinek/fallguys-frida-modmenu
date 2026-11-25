import { AndroidUtils } from "../../android/AndroidUtils";
import { FG_NetworkManager } from "../../fallguys/wrappers/FG.Common/FG_NetworkManager";
import { ClientGameManager } from "../../fallguys/wrappers/FGClient/ClientGameManager";
import { ClientGameStateView } from "../../fallguys/wrappers/FGClient/ClientGameStateView";
import { GlobalGameStateClient } from "../../fallguys/wrappers/FGClient/GlobalGameStateClient";
import { Logger } from "../../utils/Logger";
import { I18n } from "../i18n/I18n";

export class MatchInfo {
    static showGameDetails(): void {
        const gameViewInstance: ClientGameStateView | undefined = GlobalGameStateClient.instance?.gameStateView;
        if (!gameViewInstance) return;
        const gameManagerInstance: ClientGameManager | undefined = gameViewInstance.getLiveClientManager();
        if (!gameManagerInstance) return;

        const roundId = gameManagerInstance.round.id.content!;
        const seed = gameManagerInstance.randomSeed;
        const eliminatedCount = gameManagerInstance.eliminatedPlayerCount;

        const infoString = I18n.t("game_toasts.match_info", roundId, seed, eliminatedCount);
        Logger.toast(infoString, 1);
    }

    static showAndCopyServerDetails(): void {
        const networkManagerInstance: FG_NetworkManager | undefined = GlobalGameStateClient.instance?.networkManager;
        if (!networkManagerInstance) return;

        const hostIpAddr = networkManagerInstance.hostIpAddr.content!;
        const hostPortNo = networkManagerInstance.hostPortNo;
        const rtt = networkManagerInstance.gameConnection.currentRtt;

        const infoString = I18n.t("game_toasts.server_info", hostIpAddr, hostPortNo, rtt);
        Logger.toast(infoString, 1);
        AndroidUtils.copyToClipboard(`${hostIpAddr}:${hostPortNo}`);
    }
}
