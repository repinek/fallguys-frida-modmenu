import { Logger } from "../logger/Logger";

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
            } catch (error: any) {
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
            } catch (error: any) {
                Logger.errorThrow(error);
            }
        });
    }

    // Thanks a lot: https://github.com/frida/frida/issues/1158#issuecomment-1227967229
    // yeees, we can use sockets but idk I'm too lazy and it's works
    // TODO do it await or promise instead ts
    /**
     * Creates HTTP GET request using Java
     *
     * @param targetUrl URL to request
     * @param onReceive Callback function to handle response
     */
    static httpGet(targetUrl: string, onReceive: (response: string | null) => void = () => {}): void {
        Java.perform(() => {
            try {
                Logger.debug(`[${this.tag}::httpGet] HTTP GET to: ${targetUrl}`);
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
                Logger.debug(`[${this.tag}::httpGet] HTTP GET response: ${response}`);
                onReceive(response);
            } catch (error: any) {
                Logger.errorThrow(error, "HTTP GET");
                onReceive(null);
            }
        });
    }

    /**
     * Creates HTTP POST request using Java
     *
     * @param targetUrl URL to request
     * @param body Raw string content to send
     * @param headers Object with headers (e.g. { "Authorization": "Bearer 123", "Content-Type": "application/json" })
     * @param onReceive Callback function to handle response
     */
    static httpPost(targetUrl: string, body: string, headers: Record<string, string> = {}, onReceive: (response: string | null) => void = () => {}): void {
        Java.perform(() => {
            try {
                Logger.debug(`[${this.tag}::httpPost] HTTP POST to: ${targetUrl}`);

                const HttpURLConnection = Java.use("java.net.HttpURLConnection");
                const URL = Java.use("java.net.URL");
                const BufferedReader = Java.use("java.io.BufferedReader");
                const BufferedWriter = Java.use("java.io.BufferedWriter");
                const InputStreamReader = Java.use("java.io.InputStreamReader");
                const OutputStreamWriter = Java.use("java.io.OutputStreamWriter");
                const StringBuilder = Java.use("java.lang.StringBuilder");
                const StringJava = Java.use("java.lang.String");

                const url = URL.$new(targetUrl);
                const connection = Java.cast(url.openConnection(), HttpURLConnection);

                connection.setRequestMethod("POST");

                let contentTypeSet = false;

                for (const key in headers) {
                    const value = headers[key];
                    connection.setRequestProperty(key, value);

                    if (key.toLowerCase() === "content-type") {
                        contentTypeSet = true;
                    }
                }

                if (!contentTypeSet) {
                    connection.setRequestProperty("Content-Type", "application/json");
                }

                connection.setConnectTimeout(5000);
                connection.setReadTimeout(5000);
                connection.setDoInput(true);
                connection.setDoOutput(true);

                const outputStream = connection.getOutputStream();
                const writer = BufferedWriter.$new(OutputStreamWriter.$new(outputStream, StringJava.$new("UTF-8")));

                const javaBody = StringJava.$new(body);
                writer.write(javaBody, 0, javaBody.length());
                writer.flush();
                writer.close();
                outputStream.close();

                connection.connect();
                const responseCode = connection.getResponseCode();
                let response: string | null = null;

                if (responseCode === 200 || responseCode === 201) {
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
                    Logger.warn(`[${this.tag}::httpPost] Failed with code: ${responseCode}`);
                    response = null;
                }

                connection.disconnect();
                Logger.debug(`[${this.tag}::httpPost] HTTP POST response: ${response}`);
                onReceive(response);
            } catch (error: any) {
                Logger.errorThrow(error, "HTTP POST");
                onReceive(null);
            }
        });
    }
}
