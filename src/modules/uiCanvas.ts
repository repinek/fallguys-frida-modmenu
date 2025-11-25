import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { UnityUtils } from "../utils/unityUtils.js";

export class UICanvasModule extends BaseModule {
    public name = "UICanvas";

    // Classes and Instances
    private UICanvas!: Il2Cpp.Class;
    private _uiCanvasInstance!: Il2Cpp.Object;

    public init(): void {
        this.UICanvas = AssemblyHelper.MTFGClient.class("FGClient.UI.Core.UICanvas");
    }

    public toggleUICanvas(state: boolean): void {
        this.UICanvasInstance.method("SetEnabled").invoke(state);
    }

    private get UICanvasInstance(): Il2Cpp.Object {
        if (!this._uiCanvasInstance) {
            this._uiCanvasInstance = UnityUtils.findObjectsOfTypeAll(this.UICanvas).get(0);
        }
        return this._uiCanvasInstance;
    }
}
