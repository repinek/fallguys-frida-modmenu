import Java from "frida-java-bridge";

import { Logger } from "./Logger";

export class JavaUtils {
    private static readonly tag = "JavaUtils";

    /** Exits the application with code 0 */
    static exitFromApp(): void {
        Java.perform(() => {
            Logger.debug(`[${this.tag}::exitFromApp] Exiting from app`);
            const System = Java.use("java.lang.System");
            System.exit(0);
        });
    }

    /**
     * @note Use with Java.perform
     * @returns system language (like, "en", "ru")
     */
    static getSystemLocale(): string {
        const Locale = Java.use("java.util.Locale");
        const lang = Locale.getDefault().getLanguage().toLowerCase();
        Logger.debug(`[${this.tag}::getSystemLocale] Got locale from system: ${lang}`);
        return lang;
    }

    /**
     * Opens URL in default system browser
     *
     * @param targetUrl URL to open
     */
    static openURL(targetUrl: string): void {
        Java.perform(() => {
            try {
                Logger.debug(`[${this.tag}::OpenURL] Opening URL: ${targetUrl}`);
                const uri = Java.use("android.net.Uri").parse(targetUrl);
                const intent = Java.use("android.content.Intent");
                const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();

                const openIntent = intent.$new("android.intent.action.VIEW", uri);
                openIntent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
                context.startActivity(openIntent);
            } catch (error) {
                Logger.errorThrow(error);
            }
        });
    }

    /**
     * Copies text in system clipboard
     *
     * @param text Text to copy
     */
    static copyToClipboard(text: string): void {
        Java.perform(() => {
            try {
                const javaString = Java.use("java.lang.String");
                const ClipData = Java.use("android.content.ClipData");
                const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                const clipboardManager = Java.cast(context.getSystemService("clipboard"), Java.use("android.content.ClipboardManager"));

                const clipData = ClipData.newPlainText(javaString.$new("label"), javaString.$new(text));
                clipboardManager.setPrimaryClip(clipData);
                Logger.debug(`[${this.tag}::copyToClipboard] Copied to clipboard: ${text}`);
            } catch (error) {
                Logger.errorThrow(error);
            }
        });
    }
}
