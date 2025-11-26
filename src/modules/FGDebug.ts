import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { Logger } from "../logger/logger.js";
import { UnityUtils } from "../utils/unityUtils.js";

/*
 * Since the GvrFPS object is in the DontDestroyOnLoad scene, we can cache the Instance
 *
 * Scale to 0.4 (default size is too big for mobile)
 * and enable GameObject using setActive
 */

export class FGDebugModule extends BaseModule {
    public name = "FG Debug";

    // Classes and Instances
    private GvrFPS!: Il2Cpp.Class;
    private _gvrFPSInstance?: Il2Cpp.Object;

    private isScaled: boolean = false;

    public init(): void {
        this.GvrFPS = AssemblyHelper.TheMultiplayerGuys.class("GvrFPS");
    }

    public toggleFGDebug(value: boolean): void {
        try {
            this.setFGDebugScale();
            const gameObject = this.GvrFPSInstance.method<Il2Cpp.Object>("get_gameObject").invoke();
            gameObject.method("SetActive").invoke(value);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    private setFGDebugScale(): void {
        if (!this.isScaled) {
            const localScale = UnityUtils.createVector3(0.4, 0.4, 0.4);

            // prettier-ignore
            this.GvrFPSInstance
            .method<Il2Cpp.Object>("get_transform").invoke()
            .method<Il2Cpp.Object>("set_localScale").invoke(localScale);
            this.isScaled = true;
        }
        return;
    }

    private get GvrFPSInstance(): Il2Cpp.Object {
        if (!this._gvrFPSInstance) {
            this._gvrFPSInstance = UnityUtils.findObjectsOfTypeAll(this.GvrFPS).get(0);
        }
        return this._gvrFPSInstance;
    }
}
