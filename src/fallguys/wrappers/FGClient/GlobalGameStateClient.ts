import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { FG_NetworkManager } from "../FG.Common/FG_NetworkManager";
import { ClientGameStateView } from "./ClientGameStateView";
import { ClientPlayerManager } from "./ClientPlayerManager";
import { Singleton } from "./Singleton";

export class GlobalGameStateClient extends Singleton {
    protected static _class: Il2Cpp.Class | null = null;

    static override get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.MTFGClient.class("FGClient.GlobalGameStateClient"));
    }

    static override get instance(): GlobalGameStateClient | undefined {
        const object = super.instance;
        return object ? new GlobalGameStateClient(object) : undefined;
    }

    get gameStateView(): ClientGameStateView {
        return new ClientGameStateView(this.method<Il2Cpp.Object>("get_GameStateView").invoke());
    }

    get playerManager(): ClientPlayerManager {
        return new ClientPlayerManager(this.method<Il2Cpp.Object>("get_ClientPlayerManager").invoke());
    }

    get networkManager(): FG_NetworkManager {
        return new FG_NetworkManager(this.method<Il2Cpp.Object>("get_NetworkManager").invoke());
    }
}
