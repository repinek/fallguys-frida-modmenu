import { getSystemLocale } from "../utils/javaUtils.js";
import { Logger } from "../logger/logger.js";

import en from "./localization/en.json";
import ru from "./localization/ru.json";

const TRANSLATIONS: Record<string, any> = {
    en: en,
    ru: ru
};

export class I18n {
    private static supportedLocales: string[] = Object.keys(TRANSLATIONS);
    private static currentLocale: string = "en";

    public static init(): void {
        let targetLocale = "en";

        Java.perform(() => {
            if (Menu.sharedPreferences.contains("locale")) {
                const savedLocale = Menu.sharedPreferences.getString("locale");
                if (this.isLocaleSupported(savedLocale)) {
                    targetLocale = savedLocale;
                    Logger.debug(`[I18n::init] Loaded locale from config: ${targetLocale}`);
                } else 
                    Logger.warn(`[I18n::init] Locale ${savedLocale} from config is not supported`);
            } else {
                const systemLang = getSystemLocale();

                // prettier-ignore
                if (this.isLocaleSupported(systemLang)) 
                    targetLocale = systemLang;
                else 
                    Logger.warn(`[I18n::init] Locale ${systemLang} from system is not supported`);

                Menu.sharedPreferences.putString("locale", targetLocale);
                Logger.info("[I18n::init] Saved system locale to config:", targetLocale);
            }

            this.currentLocale = targetLocale;
            Logger.info(`[I18n::init] Initialized with ${targetLocale} locale`);
        });
    }

    private static isLocaleSupported(locale: string): boolean {
        return this.supportedLocales.includes(locale);
    }

    private static resolveKey(obj: any, path: string): string | undefined {
        return path.split(".").reduce((prev, curr) => {
            return prev ? prev[curr] : undefined;
        }, obj);
    }

    public static t(key: string, ...args: (string | number)[]): string {
        const value = this.resolveKey(TRANSLATIONS[this.currentLocale], key);

        if (!value) return `MISSING: ${key}`;

        if (args.length > 0) {
            // search for {n}
            return value.replace(/{(\d+)}/g, (match, number) => {
                const index = parseInt(number);
                return args[index] !== undefined ? String(args[index]) : match;
            });
        }

        return value;
    }
}
