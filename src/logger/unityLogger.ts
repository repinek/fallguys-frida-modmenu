import { AssemblyHelper } from "../core/assemblyHelper.js";
import { Config } from "../data/config.js";
import { Logger } from "./logger.js";

/*
this.DebugLogHandler = AssemblyHelper.CoreModule.class("UnityEngine.DebugLogHandler");
this.String = Il2Cpp.corlib.class("System.String");

// void UnityEngine::DebugLogHandler::LogFormat(LogType__Enum logType, Object_1 *context, String *format, Object__Array *args)
this.LogFormat = this.DebugLogHandler.method<void>("LogFormat");
this.Format = this.String.method<Il2Cpp.String>("Format", 2);
# [20:43:40] [DEBUG] "15:43:40.792: System.Object[]"
*/

export class UnityLogger {
    // Classes
    private static Debug: Il2Cpp.Class;

    // Methods
    private static Log: Il2Cpp.Method;
    private static LogWarning: Il2Cpp.Method;
    private static LogError: Il2Cpp.Method;

    public static init(): void {
        this.Debug = AssemblyHelper.CoreModule.class("UnityEngine.Debug");

        this.Log = this.Debug.method<void>("Log", 1);
        this.LogWarning = this.Debug.method("LogWarning", 1);
        this.LogError = this.Debug.method("LogError", 1);

        this.initHooks();
    }

    public static initHooks(): void {
        const module = this;

        if (Config.UNITY_LOGGING) {
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
