import { Logger } from "../utils/Logger";
import { AssemblyHelper } from "./AssemblyHelper";

export class UnityLogger {
    private static enabled: boolean = false;

    static init(enabled: boolean): void {
        UnityLogger.enabled = enabled;

        const Debug = AssemblyHelper.CoreModule.class("UnityEngine.Debug");

        //@ts-ignore
        Debug.method<void>("Log", 1).implementation = this.logHook;
        //@ts-ignore
        Debug.method("LogWarning", 1).implementation = this.warnHook;
        //@ts-ignore
        Debug.method("LogError", 1).implementation = this.errorHook;
    }

    private static logHook(this: Il2Cpp.Object, object: Il2Cpp.Object): void {
        if (UnityLogger.enabled) Logger.unity("INFO", object);
        this.method("Log", 1).invoke(object);
    }

    private static warnHook(this: Il2Cpp.Object, object: Il2Cpp.Object): void {
        if (UnityLogger.enabled) Logger.unity("WARN", object);
        this.method("LogWarning", 1).invoke(object);
    }

    private static errorHook(this: Il2Cpp.Object, object: Il2Cpp.Object): void {
        if (UnityLogger.enabled) Logger.unity("ERROR", object);
        this.method("LogError", 1).invoke(object);
    }
}
