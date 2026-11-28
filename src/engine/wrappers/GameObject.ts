import { AssemblyHelper } from "../AssemblyHelper";

/** `UnityEngine.GameObject` */
export class GameObject extends Il2Cpp.Object {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.GameObject` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.GameObject"));
    }

    /** Wrapper over UnityEngine::GameObject::SetActive */
    setActive(active: boolean): void {
        this.method<void>("SetActive").invoke(active);
    }
}
