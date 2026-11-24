import Java from "frida-java-bridge";

import { Logger } from "../utils/Logger";

// Use `Java.performNow` since we don't need access to app's classes

/**
 * This class wraps common Android operations
 * Each method already attached in Java VM, so you don't need to do it
 */
export class AndroidUtils {
    /** Exits the application with code 0 */
    static exitFromApp(): void {
        Java.performNow(() => {
            Logger.debug(`[AndroidUtils::exitFromApp] Exiting from app`);
            const System = Java.use("java.lang.System");
            System.exit(0);
        });
    }

    /**
     * @returns system language (like, "en", "ru")
     */
    static getSystemLanguage(): string {
        let lang!: string;

        Java.performNow(() => {
            const Locale = Java.use("java.util.Locale");
            lang = Locale.getDefault().getLanguage().toLowerCase();
        });

        Logger.debug(`[AndroidUtils::getSystemLanguage] Got language from system: ${lang}`);
        return lang;
    }

    /**
     * Opens URL in default system browser
     *
     * @param targetUrl URL to open
     */
    static openURL(targetUrl: string): void {
        Java.performNow(() => {
            Logger.debug(`[AndroidUtils::OpenURL] Opening URL: ${targetUrl}`);

            const uri = Java.use("android.net.Uri").parse(targetUrl);
            const intent = Java.use("android.content.Intent");
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();

            const openIntent = intent.$new("android.intent.action.VIEW", uri);
            openIntent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
            context.startActivity(openIntent);
        });
    }

    /**
     * Copies text in system clipboard
     *
     * @param text Text to copy
     */
    static copyToClipboard(text: string): void {
        Java.performNow(() => {
            const javaString = Java.use("java.lang.String");
            const ClipData = Java.use("android.content.ClipData");
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();

            const clipboardManager = Java.cast(context.getSystemService("clipboard"), Java.use("android.content.ClipboardManager"));

            const clipData = ClipData.newPlainText(javaString.$new("label"), javaString.$new(text));
            clipboardManager.setPrimaryClip(clipData);
            Logger.debug(`[AndroidUtils::copyToClipboard] Copied to clipboard: ${text}`);
        });
    }
}
