export function openURL(link: string) {
    Java.perform(() => {
        try {
            console.log(`Opening URL: ${link}`);
            const uri = Java.use("android.net.Uri").parse(link);
            const intent = Java.use("android.content.Intent");
            const activity = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();

            const openIntent = intent.$new("android.intent.action.VIEW", uri);
            openIntent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
            activity.startActivity(openIntent);
        } catch (error: any) {
            Menu.toast(`Failed to open URL: ${error.message}`, 1);
        }
    });
}

export function copyToClipboard(text: string) {
    Java.perform(() => {
        try {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const clipboardManager = Java.cast(
                context.getSystemService("clipboard"),
                Java.use("android.content.ClipboardManager")
            );
            const javaString = Java.use("java.lang.String");
            const clipData = Java.use("android.content.ClipData")
                .newPlainText(javaString.$new("label"), javaString.$new(text));
            clipboardManager.setPrimaryClip(clipData);
        } catch (error: any) {
            console.error(`Failed to copy to clipboard: ${error.message}`);
        }
    });
}

// Thanks a lot: https://github.com/frida/frida/issues/1158#issuecomment-1227967229
export function httpGet(targetUrl: string, onReceive: (response: string) => void = function(response: string) { /*console.log("response:", response);*/ }) {
    Java.perform(() => {
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");
        const URL = Java.use("java.net.URL");
        const BufferedReader = Java.use("java.io.BufferedReader");
        const InputStreamReader = Java.use("java.io.InputStreamReader");
        const StringBuilder = Java.use("java.lang.StringBuilder");

        const url = URL.$new(targetUrl);
        const conn = Java.cast(url.openConnection(), HttpURLConnection);
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setDoInput(true)
        conn.connect();
        const code = conn.getResponseCode();

        var response = null;
        if (code === 200) {
            const inputStream = conn.getInputStream();
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
            response = "error: " + code;
        }

        conn.disconnect();
        onReceive(response);
        return response;
    });
}