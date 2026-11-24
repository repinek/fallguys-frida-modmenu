/* eslint-disable @typescript-eslint/no-explicit-any */
import Java from "frida-java-bridge";
import { sharedPreferences } from "frida-java-menu";

import { AndroidUtils } from "../../android/AndroidUtils";
import { Logger } from "../../utils/Logger";
import en from "./localization/en.json";
import ru from "./localization/ru.json";

const TRANSLATIONS: Record<string, any> = {
    en: en,
    ru: ru
};

export class I18n {
    static supportedLanguages: string[] = Object.keys(TRANSLATIONS);

    private static currentLanguage: string = "en";

    static init(): void {
        const preferredLanguage = LanguagePreferences.read() || AndroidUtils.getSystemLanguage();

        const supported = this.isLanguageSupported(preferredLanguage);
        this.currentLanguage = supported ? preferredLanguage : "en";

        if (!supported) {
            Logger.warn(`[I18n::init] Unsupported language ${preferredLanguage}, using en`);
        }

        Logger.info(`[I18n::init] Initialized with ${this.currentLanguage} language`);
    }

    private static isLanguageSupported(language: string): boolean {
        return this.supportedLanguages.includes(language);
    }

    private static resolveKey(obj: any, path: string): string | undefined {
        return path.split(".").reduce((prev, curr) => {
            return prev ? prev[curr] : undefined;
        }, obj);
    }

    /** Replaces {0}, {1} placeholders with provided arguments */
    static format(text: string, ...args: (string | number)[]): string {
        if (args.length === 0) return text;

        return text.replace(/{(\d+)}/g, (match, number) => {
            const index = parseInt(number);
            return args[index] !== undefined ? String(args[index]) : match;
        });
    }

    static t(key: string, ...args: (string | number)[]): string {
        const value = this.resolveKey(TRANSLATIONS[this.currentLanguage], key);

        if (!value) return `MISSING: ${key}`;

        return this.format(value, ...args);
    }

    static getLocalisedLanguages(): string[] {
        return this.supportedLanguages.map(locale => {
            return this.t(`languages.${locale}`);
        });
    }
}

/** Class for managing Language config */
export class LanguagePreferences {
    private static key = "language";

    /** @returns undefined if no language present in sharedPreferences */
    static read(): string | undefined {
        let language: string | undefined = undefined;

        Java.performNow(() => {
            if (sharedPreferences.contains(LanguagePreferences.key)) {
                language = sharedPreferences.getString(LanguagePreferences.key);
            }
        });

        return language;
    }

    static save(newLanguage: string): void {
        Java.performNow(() => {
            sharedPreferences.putString(LanguagePreferences.key, newLanguage);
        });
    }
}
