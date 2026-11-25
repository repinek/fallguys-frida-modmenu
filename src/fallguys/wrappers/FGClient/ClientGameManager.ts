import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { Round } from "../FG.Common/CMS/Round";

export class ClientGameManager extends Il2Cpp.Object {
    protected static _class: Il2Cpp.Class | null = null;

    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.MTFGClient.class("FGClient.ClientGameManager"));
    }

    get round(): Round {
        return new Round(this.field<Il2Cpp.Object>("_round").value);
    }

    get randomSeed(): number {
        return this.method<number>("get_RandomSeed").invoke();
    }

    get eliminatedPlayerCount(): number {
        return this.field<number>("_eliminatedPlayerCount").value;
    }
}
