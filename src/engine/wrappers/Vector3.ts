import { AssemblyHelper } from "../AssemblyHelper";

/** `UnityEngine.Vector3` */
export class Vector3 {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Vector3` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Vector3"));
    }

    /** Creates a Vector3 value */
    static create(x: number, y: number, z: number): Il2Cpp.ValueType {
        const instance = this.class.alloc();
        instance.method(".ctor", 3).invoke(x, y, z);
        return instance.unbox();
    }
}
