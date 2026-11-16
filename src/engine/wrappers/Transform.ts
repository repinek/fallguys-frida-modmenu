import { AssemblyHelper } from "../AssemblyHelper";

/** `UnityEngine.Transform` */
export class Transform {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Transform` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Transform"));
    }

    /**
     * Wrapper over UnityEngine::Transform::set_localScale
     *
     * @param scale UnityEngine::Vector3
     */
    static setLocalScale(transform: Il2Cpp.Object, scale: Il2Cpp.ValueType): void {
        transform.method("set_localScale").invoke(scale);
    }
}
