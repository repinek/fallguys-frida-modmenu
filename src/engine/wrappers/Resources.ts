import { AssemblyHelper } from "../AssemblyHelper";

/** `UnityEngine.Resources` */
export class Resources {
    protected static _class: Il2Cpp.Class | null = null;

    /** `UnityEngine.Resources` */
    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.CoreModule.class("UnityEngine.Resources"));
    }

    /**
     * Gets a list of all loaded objects of type `type`, including inactive objects
     *
     * @param type A `System.Type`, accessible through `.type.object`
     */
    static findObjectsOfTypeAll(type: Il2Cpp.Object): Il2Cpp.Array<Il2Cpp.Object> {
        return this.class.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1).invoke(type);
    }
}
