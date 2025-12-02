import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { Logger } from "../../logger/logger.js";
// import { CMSLoader } from "./CMSLoader.js";

// TODO: describe

export class LocalisedStrings {
    private static readonly tag = "LocalisedStrings";

    // Classes
    private static LocalisedStrings: Il2Cpp.Class;

    // Methods
    private static GetString: Il2Cpp.Method;

    static init(): void {
        this.LocalisedStrings = AssemblyHelper.TheMultiplayerGuys.class("LocalisedStrings");

        this.GetString = this.LocalisedStrings.method<Il2Cpp.String>("GetString", 1);

        this.initHooks();

        Logger.info(`[${this.tag}::init] Initialized`);
    }

    private static initHooks(): void {
        // @ts-ignore
        this.GetString.implementation = function (id: Il2Cpp.String): Il2Cpp.String {
            const result = this.method<Il2Cpp.String>("GetString", 1).invoke(id);

            const originalText = result.content;
            const originalId = id.content;

            if (originalText === `[${originalId}]`) {
                return id;
            }
            return result;
        };
    }
}

/*
export class GameLocalization {
    private static readonly tag = "GameLocalization";
    // Instances
    static LocalisedStringsInstance: Il2Cpp.Object;

    private static dynamicKeys = new Map<string, string>();
    private static keyCounter = 0;

    static init(): void {
        this.LocalisedStringsInstance = CMSLoader.CMSLoaderInstance!.field<Il2Cpp.Object>("_localisedStrings").value;
        Logger.info(`[${this.tag}::init] Initialized`);
    }

    static Add(key: string, value: string): void {
        const localisedStringsDict = this.LocalisedStringsInstance.field<Il2Cpp.Object>("_localisedStrings").value;
        localisedStringsDict.method("Add").invoke(Il2Cpp.string(key), Il2Cpp.string(value));
    }

    static getOrCreateKey(text: string): string {
        if (this.dynamicKeys.has(text)) {
            return this.dynamicKeys.get(text)!;
        }

        const key = `mod_menu_${this.keyCounter++}`;
        this.Add(key, text);
        this.dynamicKeys.set(text, key);

        Logger.debug(`Created localised string, key: ${key}, value: ${text}`);
        return key;
    }
}
*/
