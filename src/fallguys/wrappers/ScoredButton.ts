import { AssemblyHelper } from "../../engine/AssemblyHelper";
import { Component } from "../../engine/wrappers/Component";

export class ScoredButton extends Component {
    protected static override _class: Il2Cpp.Class | null = null;

    static override get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.TheMultiplayerGuys.class("ScoredButton"));
    }

    get isAnActiveTarget(): boolean {
        return this.field<boolean>("_isAnActiveTarget").value;
    }
}
