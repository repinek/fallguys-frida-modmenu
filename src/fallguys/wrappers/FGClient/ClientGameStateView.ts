import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { Logger } from "../../../utils/Logger";
import { ClientGameManager } from "./ClientGameManager";

/** Wrapper over `FGClient.ClientGameStateView` */
export class ClientGameStateView extends Il2Cpp.Object {
    protected static _class: Il2Cpp.Class | null = null;

    /** `FGClient.ClientGameStateView` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.MTFGClient.class("FGClient.ClientGameStateView"));
    }

    get isGamePlaying(): boolean {
        return this.method<boolean>("get_IsGamePlaying").invoke();
    }

    getLiveClientManager(): ClientGameManager | undefined {
        const mem = Memory.alloc(Process.pointerSize);
        const out = new Il2Cpp.Reference<Il2Cpp.Object>(mem, ClientGameManager.class.type);
        const isSuccess = this.method<boolean>("GetLiveClientGameManager").invoke(out);
        if (!isSuccess) {
            Logger.warn("[ClientGameStateView::getLiveClientManager] Can't get ClientGameManager");
            return undefined;
        }

        return new ClientGameManager(out.value);
    }
}
