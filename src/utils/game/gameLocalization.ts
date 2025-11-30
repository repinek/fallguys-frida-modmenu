import { Logger } from "../../logger/logger.js";
import { CMSLoader } from "./CMSLoader.js";

export class GameLocalization {
    // Instances
    static LocalisedStringsInstance: Il2Cpp.Object;

    private static dynamicKeys = new Map<string, string>();
    private static keyCounter = 0;

    static init(): void {
        this.LocalisedStringsInstance = CMSLoader.CMSLoaderInstance!.field<Il2Cpp.Object>("_localisedStrings").value;
        Logger.info("[GameLocalization::init] Initialized");
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

        return key;
    }
}
