import { AssemblyHelper } from "../AssemblyHelper";

// This is taken from https://github.com/repinek/SonolusReverse/blob/9188c887daea7cf7c3cfa82b81b600ac3b24c199/src/engine/wrappers/Object.ts

/**
 * `UnityEngine.Object` - base class for all objects Unity can reference
 *
 * Only static methods are wrapped here
 */
// ts(2725): Class name cannot be `Object` when targeting ES5 and above with module NodeNext.
// That's why it is named UEObject - Unity Engine Object
// Not Il2Cpp.Object - this wraps the managed C# type
export class UEObject {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Object` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Object"));
    }

    /**
     * Gets a list of all loaded objects of type `type`
     *
     * @param type A `System.Type`, accessible through `.type.object`
     */
    static findObjectsOfType(type: Il2Cpp.Object, includeInactive: boolean): Il2Cpp.Array<Il2Cpp.Object> {
        return this.class.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfType", 2).invoke(type, includeInactive);
    }

    // Wtf, I can't find any documentation for this one, so no JSDoc
    static findObjectFromInstanceID(id: number): Il2Cpp.Object | undefined {
        const object = this.class.method<Il2Cpp.Object>("FindObjectFromInstanceID", 1).invoke(id);
        if (object.isNull()) return undefined;
        return object;
    }

    /** Gets the instance ID of the object */
    static getInstanceID(object: Il2Cpp.Object): number {
        return object.method<number>("GetInstanceID").invoke();
    }
}
