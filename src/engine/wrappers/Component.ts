import { AssemblyHelper } from "../AssemblyHelper";

/** `UnityEngine.Component` */
export class Component {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Component` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Component"));
    }

    /** Wrapper over UnityEngine::Compontent::get_gameObject */
    static getGameObject(component: Il2Cpp.Object): Il2Cpp.Object {
        return component.method<Il2Cpp.Object>("get_gameObject").invoke();
    }

    /** Wrapper over UnityEngine::Compontent::get_transform */
    static getTransform(component: Il2Cpp.Object): Il2Cpp.Object {
        return component.method<Il2Cpp.Object>("get_transform").invoke();
    }
}
