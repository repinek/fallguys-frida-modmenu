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
            const GameStateInstance = UnityUtils.getInstance(this.GlobalGameStateClient);

            if (!GameStateInstance) {
                return;
            }

            if (!GameStateInstance.method<boolean>("get_IsInGameplay").invoke()) {
                Logger.warn(`[${this.name}::showGameDetails] Not in the game`);
                Logger.toast(I18n.t("game_toasts.not_in_match"));
                return;
            }

            // TODO: describe. we need CGM 
            const gameStateView = GameStateInstance.method<Il2Cpp.Object>("get_GameStateView").invoke();
            const mem = Memory.alloc(Process.pointerSize);
            const out = new Il2Cpp.Reference<Il2Cpp.Object>(mem, this.ClientGameManager.type)
            const isSuccess = gameStateView.method<boolean>("GetLiveClientGameManager").invoke(out);
            
            if (!isSuccess) {
                return;
            }

            const GameManagerInstance = out.value;
            const round = GameManagerInstance.field<Il2Cpp.Object>("_round").value;
            const roundID = round.method<Il2Cpp.String>("get_Id").invoke().content!;
            const seed = GameManagerInstance.method<number>("get_RandomSeed").invoke();
            const eliminatedCount = GameManagerInstance.field<number>("_eliminatedPlayerCount").value;

            const infoString = I18n.t("game_toasts.match_info", roundID, seed, eliminatedCount);
            Logger.toast(infoString, 1);

            // // allocate memory for the out argument
            // const outCGMPtr = Memory.alloc(Process.pointerSize);

            // // pass the allocated pointer to the method
            // // method returns true if it found Client Game Manager in my case
            // const isSuccess = gameStateView.method<boolean>("GetLiveClientGameManager").invoke(outCGMPtr);

            // if (isSuccess) {
            //     // read the object address that the game wrote into our memory
            //     const cgmPointer = outCGMPtr.readPointer();

            //     // create a new Il2Cpp.Object using our raw pointer
            //     const ClientGameManagerInstance = new Il2Cpp.Object(cgmPointer);
            //     Logger.debug(ClientGameManagerInstance);

            //     // read anything just for check
            //     const playersNumber = ClientGameManagerInstance.field<number>("_initialNumParticipants").value;
            //     Logger.debug(playersNumber);
            // }

            // if (isSuccess) {
            //     const cgmHandle = outCgmPtr.readPointer();
            //     const CGM = new Il2Cpp.Object(cgmHandle);
            //     Logger.debug(CGM);
            // }
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    public showServerDetails(): void {
        try {
            const GameStateInstance = UnityUtils.getInstance(this.GlobalGameStateClient);

            if (!GameStateInstance) {
                return;
            }

            // TODO: made this checks in teleportmanager -> move it to ../game/
            if (!GameStateInstance.method<boolean>("get_IsInGameplay").invoke()) {
                Logger.warn(`[${this.name}::showServerDetails] Not in the game`);
                Logger.toast(I18n.t("game_toasts.not_in_match"));
                return;
            }

            const networkManager = GameStateInstance.method<Il2Cpp.Object>("get_NetworkManager").invoke();
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
