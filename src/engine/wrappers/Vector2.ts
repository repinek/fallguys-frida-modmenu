import { AssemblyHelper } from "../AssemblyHelper";

/** `UnityEngine.Vector2` */
export class Vector2 extends Il2Cpp.ValueType {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Vector2` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Vector2"));
    }

    /** Creates a Vector2 value */
    static create(x: number, y: number): Il2Cpp.ValueType {
        const instance = this.class.alloc();
        instance.method(".ctor", 2).invoke(x, y);
        return instance.unbox();
    }
}
