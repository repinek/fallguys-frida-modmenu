import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { UnityUtils } from "../../utils/UnityUtils";

export class UICanvasModule extends BaseModule {
    public readonly name = "UICanvas";

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
            this._uiCanvasInstance = UnityUtils.FindObjectsOfTypeAll(this.UICanvas).get(0);
        }
        return this._uiCanvasInstance;
    }
}
