import { Logger } from "../../utils/Logger";
import { AssemblyHelper } from "../AssemblyHelper";
import { System } from "../System";

type SendResult = Omit<UnityWebRequest, "sendWebRequest">;

/** `UnityEngine.UnityWebRequest` */
export class UnityWebRequest extends Il2Cpp.Object {
    protected static _class: Il2Cpp.Class | null = null;

    static get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.UnityWebRequestModule.class("UnityEngine.Networking.UnityWebRequest"));
    }

    get responseCode(): number {
        return this.method<Int64>("get_responseCode").invoke().toNumber();
    }

    get error(): string {
        const str = this.method<Il2Cpp.String>("get_error").invoke();
        return str.isNull() ? "" : (str.content ?? "");
    }

    get text(): string {
        const handler = this.method<Il2Cpp.Object>("get_downloadHandler").invoke();
        if (handler.isNull()) return "";
        const str = handler.method<Il2Cpp.String>("get_text").invoke();
        return str.isNull() ? "" : (str.content ?? "");
    }

    dispose(): void {
        this.method<void>("Dispose").invoke();
    }

    async sendWebRequest(): Promise<UnityWebRequest> {
        return new Promise(resolve => {
            this.method<void>("set_timeout", 1).invoke(5);
            const operation = this.method<Il2Cpp.Object>("SendWebRequest").invoke();

            const AsyncOperation = AssemblyHelper.CoreModule.class("UnityEngine.AsyncOperation");
            const callbackClass = System.Action1.inflate(AsyncOperation);

            // Add our callback on complete
            operation.method<void>("add_completed", 1).invoke(Il2Cpp.delegate(callbackClass, () => resolve(this)));
        });
    }

    private static get(uri: string): UnityWebRequest {
        const request = UnityWebRequest.class.method<Il2Cpp.Object>("Get").invoke(Il2Cpp.string(uri));
        return new UnityWebRequest(request);
    }

    static async sendGet(uri: string): Promise<SendResult> {
        Logger.debug(`[UnityWebRequest::sendGet] ${uri}`);
        const request = UnityWebRequest.get(uri);
        const result = await request.sendWebRequest();

        if (result.responseCode != 200) {
            const error = result.error;
            const content = result.text;
            request.dispose();
            throw new Error(`Response code is not 200\nError: ${error}\nContent: ${content}`);
        }

        return result
    }
}
