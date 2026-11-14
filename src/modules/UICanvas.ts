import { AssemblyHelper } from "../core/AssemblyHelper";
import { UnityUtils } from "../utils/UnityUtils";
import { Logger } from "../logger/Logger";

export class UICanvas {
    // Classes and Instances
    private static UICanvas: Il2Cpp.Class;
    private static _uiCanvasInstance: Il2Cpp.Object;

    static init(): void {
        this.UICanvas = AssemblyHelper.MTFGClient.class("FGClient.UI.Core.UICanvas");

        Logger.info("[UICanvas::init] Initialized");
    }

    static toggleUICanvas(state: boolean): void {
        this.UICanvasInstance.method("SetEnabled").invoke(state);
    }

    private static get UICanvasInstance(): Il2Cpp.Object {
        if (!this._uiCanvasInstance) {
            this._uiCanvasInstance = UnityUtils.FindObjectsOfTypeAll(this.UICanvas).get(0);
        }
        return this._uiCanvasInstance;
    }
}
