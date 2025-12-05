import { JavaUtils } from "../utils/JavaUtils";
import { Logger } from "../logger/Logger";

import en from "./localization/en.json";
import ru from "./localization/ru.json";

const TRANSLATIONS: Record<string, any> = {
    en: en,
    ru: ru
};

export class I18n {
    private static readonly tag = "I18n";

    static supportedLocales: string[] = Object.keys(TRANSLATIONS);
    private static currentLocale: string = "en";

    static init(): void {
        let targetLocale = "en";

        Java.perform(() => {
            if (Menu.sharedPreferences.contains("locale")) {
                const savedLocale = Menu.sharedPreferences.getString("locale");
                if (this.isLocaleSupported(savedLocale)) {
                    targetLocale = savedLocale;
                    Logger.debug(`[${this.tag}::init] Loaded locale from config: ${targetLocale}`);
                } else Logger.warn(`[${this.tag}::init] Locale ${savedLocale} from config is not supported`);
            } else {
                const systemLang = JavaUtils.getSystemLocale();

                // prettier-ignore
                if (this.isLocaleSupported(systemLang)) 
                    targetLocale = systemLang;
                else 
                    Logger.warn(`[${this.tag}::init] Locale ${systemLang} from system is not supported`);

                Menu.sharedPreferences.putString("locale", targetLocale);
                Logger.info(`[${this.tag}::init] Saved ${targetLocale} locale to config`);
            }

            this.currentLocale = targetLocale;
            Logger.info(`[${this.tag}::init] Initialized with ${targetLocale} locale`);
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

    static t(key: string, ...args: (string | number)[]): string {
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

    static getLocalisedLanguages(): string[] {
        return this.supportedLocales.map(locale => {
            return this.t(`languages.${locale}`);
        });
    }

    static changeLocale(newLocale: string): void {
        if (!this.isLocaleSupported(newLocale)) {
            Logger.warn(`[${this.tag}::changeLocale] Trying to apply unsupported locale ${newLocale}`);
            return;
        }

        Java.perform(() => {
            Menu.sharedPreferences.putString("locale", newLocale);
        });

        Logger.info(`[${this.tag}::changeLocale] Locale changed to: ${newLocale}`);
    }
}
