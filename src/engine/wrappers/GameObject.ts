import { AssemblyHelper } from "../AssemblyHelper";

/** `UnityEngine.GameObject` */
export class GameObject {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.GameObject` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.GameObject"));
    }

    /** Wrapper over UnityEngine::GameObject::SetActive */
    static setActive(gameObject: Il2Cpp.Object, active: boolean): void {
        gameObject.method<void>("SetActive").invoke(active);
    }
}
