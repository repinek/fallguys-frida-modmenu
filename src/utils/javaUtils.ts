import { Logger } from "./logger.js";

export function exitFromApp() {
    Java.perform(() => {
        Logger.debug("Exiting from app");
        const System = Java.use("java.lang.System");
        System.exit(0);
    });
}

/** Use with Java.perform */
export function getSystemLocale() {
    const Locale = Java.use("java.util.Locale");
    const lang = Locale.getDefault().getLanguage().toLowerCase();
    Logger.debug("System Locale:", lang);
    return lang;
}

export function openURL(targetUrl: string) {
    Java.perform(() => {
        try {
            Logger.debug(`Opening URL: ${targetUrl}`);
            const uri = Java.use("android.net.Uri").parse(targetUrl);
            const intent = Java.use("android.content.Intent");
            const activity = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();

            const openIntent = intent.$new("android.intent.action.VIEW", uri);
            openIntent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
            activity.startActivity(openIntent);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    });
}

export function copyToClipboard(text: string) {
    Java.perform(() => {
        try {
            const javaString = Java.use("java.lang.String");
            const ClipData = Java.use("android.content.ClipData");
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const clipboardManager = Java.cast(context.getSystemService("clipboard"), Java.use("android.content.ClipboardManager"));

            const clipData = ClipData.newPlainText(javaString.$new("label"), javaString.$new(text));
            clipboardManager.setPrimaryClip(clipData);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    });
}

// Thanks a lot: https://github.com/frida/frida/issues/1158#issuecomment-1227967229
export function httpGet(targetUrl: string, onReceive: (response: string | null) => void = () => {}) {
    Java.perform(() => {
        try {
            Logger.debug(`HTTP GET: ${targetUrl}`);
            const HttpURLConnection = Java.use("java.net.HttpURLConnection");
            const URL = Java.use("java.net.URL");
            const BufferedReader = Java.use("java.io.BufferedReader");
            const InputStreamReader = Java.use("java.io.InputStreamReader");
            const StringBuilder = Java.use("java.lang.StringBuilder");

            const url = URL.$new(targetUrl);
            const connection = Java.cast(url.openConnection(), HttpURLConnection);

            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setDoInput(true);
            connection.connect();

            const responseCode = connection.getResponseCode();
            let response: string | null = null;

            if (responseCode === 200) {
                const inputStream = connection.getInputStream();
                const buffer = BufferedReader.$new(InputStreamReader.$new(inputStream));
                const sb = StringBuilder.$new();

                let line: string | null;
                while ((line = buffer.readLine()) != null) {
                    sb.append(line);
                }

                response = sb.toString();

                inputStream.close();
                buffer.close();
            } else {
                response = null;
            }

            connection.disconnect();
            Logger.debug("HTTP GET response:", response);
            onReceive(response);
            return response;
        } catch (error: any) {
            Logger.errorThrow(error, "HTTP GET");
            onReceive(null);
            return null;
        }
    });
}
