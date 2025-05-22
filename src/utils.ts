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