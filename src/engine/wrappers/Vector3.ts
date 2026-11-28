import { AssemblyHelper } from "../AssemblyHelper";

/** `UnityEngine.Vector3` */
export class Vector3 extends Il2Cpp.ValueType {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Vector3` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Vector3"));
    }

    /** Creates a Vector3 value */
    static create(x: number, y: number, z: number): Vector3 {
        const instance = this.class.alloc();
        instance.method(".ctor", 3).invoke(x, y, z);
        const value = instance.unbox();
        return new Vector3(value.handle, value.type);
    }

    get y(): number {
        return this.field<number>("y").value;
    }

    set y(value: number) {
        this.field<number>("y").value = value;
    }
}
