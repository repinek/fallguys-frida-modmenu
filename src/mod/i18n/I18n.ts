/* eslint-disable @typescript-eslint/no-explicit-any */
import Java from "frida-java-bridge";
import { sharedPreferences } from "frida-java-menu";

import { JavaUtils } from "../../utils/JavaUtils";
import { Logger } from "../../utils/Logger";
import en from "./localization/en.json";
import ru from "./localization/ru.json";

const TRANSLATIONS: Record<string, any> = {
    en: en,
    ru: ru
};

export class I18n {
    static supportedLocales: string[] = Object.keys(TRANSLATIONS);

    private static currentLocale: string = "en";

    static init(): void {
        let targetLocale = "en";

        Java.perform(() => {
            const isSaved = sharedPreferences.contains("locale");
            const locale = isSaved ? sharedPreferences.getString("locale") : JavaUtils.getSystemLocale();

            // Check if locale from config or system is supported, and assign it if supported
            if (this.isLocaleSupported(locale)) {
                targetLocale = locale;
                if (isSaved) Logger.debug(`[I18n::init] Loaded locale from config: ${targetLocale}`);
            } else {
                const source = isSaved ? "config" : "system";
                Logger.warn(`[I18n::init] Locale ${locale} from ${source} is not supported`);
            }

            // Save locale if not saved yet
            if (!isSaved) {
                sharedPreferences.putString("locale", targetLocale);
                Logger.info(`[I18n::init] Saved ${targetLocale} locale to config`);
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

    /** Replaces {0}, {1} placeholders with provided arguments */
    public static format(text: string, ...args: (string | number)[]): string {
        if (args.length === 0) return text;

        return text.replace(/{(\d+)}/g, (match, number) => {
            const index = parseInt(number);
            return args[index] !== undefined ? String(args[index]) : match;
        });
    }

    static t(key: string, ...args: (string | number)[]): string {
        const value = this.resolveKey(TRANSLATIONS[this.currentLocale], key);

        if (!value) return `MISSING: ${key}`;

        return this.format(value, ...args);
    }

    static getLocalisedLanguages(): string[] {
        return this.supportedLocales.map(locale => {
            return this.t(`languages.${locale}`);
        });
    }

    static changeLocale(newLocale: string): void {
        if (!this.isLocaleSupported(newLocale)) {
            Logger.warn(`[I18n::changeLocale] Trying to apply unsupported locale ${newLocale}`);
            return;
        }

        Java.perform(() => {
            sharedPreferences.putString("locale", newLocale);
        });

        Logger.info(`[I18n::changeLocale] Locale changed to: ${newLocale}`);
    }
}
