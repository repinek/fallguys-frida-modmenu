import { UnityUtils } from "../../../engine/UnityUtils";

/** `MPG.Utility.Singleton` - Base class for singleton classes with a single instance */
export abstract class Singleton extends Il2Cpp.Object {
    static get class(): Il2Cpp.Class {
        // return (this._class ??= AssemblyHelper.assembly.class("ClassName");
        throw new Error(`You must override class in ${this.name}`);
    }

    static get instance(): Il2Cpp.Object | undefined {
        return UnityUtils.getInstance(this.class);
    }
}
