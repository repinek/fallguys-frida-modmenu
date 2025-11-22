import { getSystemLocale } from "../utils.js";
import { Logger } from "../logger.js";

import en from "./localization/en.json";
import ru from "./localization/ru.json";

const TRANSLATIONS: Record<string, any> = {
    en: en,
    ru: ru
};

export class I18n {
    private static supportedLocales: string[] = Object.keys(TRANSLATIONS);
    private static currentLocale: string = "en";

    public static init() {
        let targetLocale = "en";

        // Current thread is not attached to the Java VM; please move this code inside a Java.perform() callback
        // IM SO FUCKING STUPID OMG
        Java.perform(() => {
            if (Menu.sharedPreferences.contains("locale")) {
                const savedLocale = Menu.sharedPreferences.getString("locale");
                if (this.isLocaleSupported(savedLocale)) {
                    targetLocale = savedLocale;
                    Logger.debug(`[I18n] Loaded locale from config: ${targetLocale}`);
                } else {
                    Logger.warn(`[I18n] Locale ${savedLocale} from config is not supported`);
                }
            } else {
                const systemLang = getSystemLocale();

                if (this.isLocaleSupported(systemLang)) targetLocale = systemLang;
                else Logger.warn(`[I18n] Locale ${systemLang} from system is not supported`);

                Menu.sharedPreferences.putString("locale", targetLocale);
                Logger.debug("[I18n] Saved system locale to config:", targetLocale);
            }
        });

        this.currentLocale = targetLocale;
    }

    private static isLocaleSupported(locale: string): boolean {
        return this.supportedLocales.includes(locale);
    }

    public static t(key: string): string {
        const value = this.resolveKey(TRANSLATIONS[this.currentLocale], key);

        if (!value) return key;

        return value;
    }

    private static resolveKey(obj: any, path: string): string | undefined {
        return path.split(".").reduce((prev, curr) => {
            return prev ? prev[curr] : undefined;
        }, obj);
    }
}
