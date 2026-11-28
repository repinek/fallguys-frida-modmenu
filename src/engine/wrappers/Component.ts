import { AssemblyHelper } from "../AssemblyHelper";
import { GameObject } from "./GameObject";
import { Vector3 } from "./Vector3";

/** `UnityEngine.Component` */
export class Component extends Il2Cpp.Object {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Component` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Component"));
    }

    /** Wrapper over UnityEngine::Compontent::get_gameObject */
    get gameObject(): GameObject {
        return new GameObject(this.method<Il2Cpp.Object>("get_gameObject").invoke());
    }

    /** Wrapper over UnityEngine::Compontent::get_transform */
    get transform(): Transform {
        return new Transform(this.method<Il2Cpp.Object>("get_transform").invoke());
    }
}

/** `UnityEngine.Transform` */
export class Transform extends Component {
    protected static override _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Transform` */
    static override get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Transform"));
    }

    /**
     * Wrapper over UnityEngine::Transform::set_localScale
     *
     * @param scale UnityEngine::Vector3
     */
    setLocalScale(scale: Vector3): void {
        this.method("set_localScale").invoke(scale);
    }
}
