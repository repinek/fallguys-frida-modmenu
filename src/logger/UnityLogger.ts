import { AssemblyHelper } from "../core/AssemblyHelper";
import { Constants } from "../data/Constants";
import { Logger } from "./Logger";

export class UnityLogger {
    // Classes
    private static Debug: Il2Cpp.Class;

    // Methods
    private static Log: Il2Cpp.Method;
    private static LogWarning: Il2Cpp.Method;
    private static LogError: Il2Cpp.Method;

    static init(): void {
        this.Debug = AssemblyHelper.CoreModule.class("UnityEngine.Debug");

        this.Log = this.Debug.method<void>("Log", 1);
        this.LogWarning = this.Debug.method("LogWarning", 1);
        this.LogError = this.Debug.method("LogError", 1);

        this.initHooks();
    }

    static initHooks(): void {
        const module = this;

        if (Constants.UNITY_LOGGING) {
            //@ts-ignore
            this.Log.implementation = function (object: Il2Cpp.Object): void {
                Logger.unity("INFO", object);
                module.Log.invoke(object);
            };

            //@ts-ignore
            this.LogWarning.implementation = function (object: Il2Cpp.Object): void {
                Logger.unity("WARN", object);
                module.LogWarning.invoke(object);
            };

            //@ts-ignore
            this.LogError.implementation = function (object: Il2Cpp.Object): void {
                Logger.unity("ERROR", object);
                module.LogError.invoke(object);
            };
        }
    }
}
