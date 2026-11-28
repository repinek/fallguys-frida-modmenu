import { AssemblyHelper } from "../../../../engine/AssemblyHelper";
import { Component } from "../../../../engine/wrappers/Component";

export class SpawnableCollectable extends Component {
    protected static override _class: Il2Cpp.Class | null = null;

    static override get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"));
    }

    get spawned(): boolean {
        return this.method<boolean>("get_Spawned").invoke();
    }
}
