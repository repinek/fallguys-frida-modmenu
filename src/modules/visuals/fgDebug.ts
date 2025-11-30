import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { Logger } from "../../logger/logger.js";
import { UnityUtils } from "../../utils/unityUtils.js";

/*
 * Since the GvrFPS object is in the DontDestroyOnLoad scene, we can cache the Instance
 *
 * Scale to 0.4 (default size is too big for mobile)
 * and enable GameObject using setActive
 * 
 * also we need Awake hook, since menu is loading faster than fgdebug instance in the game, and we got:
 * [ERROR]  il2cpp: cannot get element at index 0 as the array length is 0
 */

export class FGDebugModule extends BaseModule {
    public readonly name = "FGDebug";

    // Classes and Instances
    private GvrFPS!: Il2Cpp.Class;
    private _gvrFPSInstance?: Il2Cpp.Object;

    // Methods
    private Awake!: Il2Cpp.Method;

    private isToggled: boolean = false;
    private isAwaked: boolean = false;
    private isScaled: boolean = false;

    public init(): void {
        this.GvrFPS = AssemblyHelper.TheMultiplayerGuys.class("GvrFPS");

        this.Awake = this.GvrFPS.method<void>("Awake");
    }

    public override initHooks(): void {
        const module = this;

        this.Awake.implementation = function (): void {
            Logger.hook("GvrFPS::Awake called");
            this.method<void>("Awake").invoke(); // <--- OnLeave
            module.isAwaked = true;
            if (module.isToggled)
                module.toggleFGDebug(true);
        }
    }   

    public toggleFGDebug(value: boolean): void {
        try {   
            this.isToggled = true;
            if (this.isAwaked) {
                this.setFGDebugScale();
                const gameObject = this.GvrFPSInstance.method<Il2Cpp.Object>("get_gameObject").invoke();
                gameObject.method("SetActive").invoke(value);
            }
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
