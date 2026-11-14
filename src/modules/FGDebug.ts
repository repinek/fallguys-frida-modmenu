import { AssemblyHelper } from "../core/AssemblyHelper";
import { Logger } from "../logger/Logger";
import { UnityUtils } from "../utils/UnityUtils";

/*
 * Since the GvrFPS object is in the DontDestroyOnLoad scene, we can cache the Instance
 *
 * Scale to 0.4 (default size is too big for mobile)
 * and enable GameObject using setActive
 *
 * also we need Awake hook, since our menu is loading faster than fgdebug instance in the game, and we got:
 * [ERROR]  il2cpp: cannot get element at index 0 as the array length is 0
 */

export class FGDebug {
    private static GvrFPS: Il2Cpp.Class;
    private static _gvrFPSInstance: Il2Cpp.Object;

    private static shouldToggled: boolean = false;
    private static isAwaked: boolean = false;
    private static isScaled: boolean = false;

    static init(): void {
        this.GvrFPS = AssemblyHelper.TheMultiplayerGuys.class("GvrFPS");

        // @ts-ignore
        this.GvrFPS.method<void>("Awake").implementation = this.awakeHook;

        Logger.info("[FGDebug::init] Initialized");
    }

    private static awakeHook(this: Il2Cpp.Object): void {
        Logger.hook("GvrFPS::Awake called");
        this.method<void>("Awake").invoke(); // <--- OnLeave
        FGDebug.isAwaked = true;
        FGDebug.toggleFGDebug(FGDebug.shouldToggled);
    }

    static toggleFGDebug(value: boolean): void {
        this.shouldToggled = value;

        if (this.isAwaked) {
            this.setFGDebugScale();
            const gameObject = this.GvrFPSInstance.method<Il2Cpp.Object>("get_gameObject").invoke();
            UnityUtils.SetActive(gameObject, value);
        }
    }

    private static setFGDebugScale(): void {
        if (!this.isScaled) {
            const localScale = UnityUtils.createVector3(0.4, 0.4, 0.4);

            // prettier-ignore
            const transform = UnityUtils.getTransform(this.GvrFPSInstance);
            UnityUtils.setLocalScale(transform, localScale);
            this.isScaled = true;
        }
        return;
    }

    private static get GvrFPSInstance(): Il2Cpp.Object {
        if (!this._gvrFPSInstance) {
            this._gvrFPSInstance = UnityUtils.FindObjectsOfTypeAll(this.GvrFPS).get(0);
        }
        return this._gvrFPSInstance;
    }
}
