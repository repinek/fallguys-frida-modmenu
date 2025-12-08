import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { Constants } from "../../data/Constants";
import { ModSettings } from "../../data/ModSettings";
import { I18n } from "../../i18n/I18n";
import { Logger } from "../../logger/Logger";
import { LocaliseOption } from "../../ui/popup/data/ModalMessageBaseData";
import { ModalType, OkButtonType } from "../../ui/popup/data/ModalMessageData";
import { ModalMessageWithInputFieldData } from "../../ui/popup/data/ModalMessageWithInputFieldData";
import { PopupManager } from "../../ui/popup/PopupManager";
import { JavaUtils } from "../../utils/JavaUtils";
import { UnityUtils } from "../../utils/UnityUtils";

// SHITCODE ALERT!

/**
 * 1. Hook PerformLoginFlow:
 *    We are pausing the game's attempt to log in.
 *    Instead of logging in, we show an Input Popup to the user.
 *
 * 2. Access Token:
 *    User pastes a Refresh Token -> We send HTTP POST to Constants.TOKEN_URL -> We get a valid Access Token to login.
 *
 * 3. Resume:
 *    We call the original PerformLoginFlow again, see resumeLogin() (with a flag to avoid infinite loops).
 *    BuildLoginRequest hook for change our token
 *
 * Thx floyzi
 */

export class TokenLoginModule extends BaseModule {
    public readonly name = "TokenLogin";

    // Classes
    private CatapultGatewayConnection!: Il2Cpp.Class;
    private LoginState!: Il2Cpp.Class;

    // Methods
    private PerformLoginFlow!: Il2Cpp.Method;
    private BuildLoginRequest!: Il2Cpp.Method;

    private args?: [Il2Cpp.Object, Il2Cpp.Object];
    private isPerformingLogin = false;
    private accessToken: string | null = null;

    public init(): void {
        this.CatapultGatewayConnection = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Gateway.CatapultGatewayConnection");
        this.LoginState = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Gateway.States.LoginState");

        this.PerformLoginFlow = this.CatapultGatewayConnection.method("PerformLoginFlow", 1);
        this.BuildLoginRequest = this.LoginState.method<Il2Cpp.Object>("BuildLoginRequest", 1);
    }

    public override initHooks(): void {
        const module = this;

        //@ts-ignore
        this.PerformLoginFlow.implementation = function (this: Il2Cpp.Object, ContentUpdateNotification: Il2Cpp.Object): void {
            Logger.hook("PerformLoginFlow called");

            if (module.isPerformingLogin || !ModSettings.tokenLogin) {
                module.isPerformingLogin = false;
                return this.method<void>("PerformLoginFlow", 1).invoke(ContentUpdateNotification);
            }

            // This is bad implemenation!
            module.args = [this, ContentUpdateNotification];

            module.showTokenPopup();
        };

        //@ts-ignore
        this.BuildLoginRequest.implementation = function (LoginCredential: Il2Cpp.Object): Il2Cpp.Object {
            Logger.hook("BuildLoginRequest called");
            const httpLoginRequest = this.method<Il2Cpp.Object>("BuildLoginRequest", 1).invoke(LoginCredential);

            if (ModSettings.tokenLogin && module.accessToken) {
                httpLoginRequest.method("set_Token", 1).invoke(Il2Cpp.string(module.accessToken));
                Logger.debug(`[${module.name}::BuildLoginRequest] Using custom token to login`);
            }

            return httpLoginRequest;
        };
    }

    private showTokenPopup(): void {
        const data = ModalMessageWithInputFieldData.create();
        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = I18n.t("popups.token_login.title");
        data.Message = I18n.t("popups.token_login.message");
        data.MessageAdditional = I18n.t("popups.token_login.message_additional");
        data.InputTextPlaceholder = I18n.t("popups.token_login.placeholder");

        data.ModalType = ModalType.MT_OK_CANCEL;
        data.OkButtonType = OkButtonType.Green;

        data.OnInputFieldModalClosed = Il2Cpp.delegate(UnityUtils.SystemActionBoolString, (pressed: boolean, input: Il2Cpp.String) => {
            Logger.debug(`pressed: ${pressed}, ${input}`);

            const token = input.content?.trim();
            if (pressed && token && this.validateToken(token)) {
                this.refreshToAccessToken(token);
            } else {
                this.resumeLogin();
            }
        });

        PopupManager.show(data, 1.5);
    }

    private refreshToAccessToken(refreshToken: string): void {
        const body = I18n.format(Constants.TOKEN_BODY, refreshToken);
        const headers = { "Content-Type": "application/x-www-form-urlencoded", Authorization: Constants.TOKEN_AUTHORIZATION };

        JavaUtils.httpPost(Constants.TOKEN_URL, body, headers, response => {
            if (!response) {
                Logger.warn(`[${this.name}::refreshToAccessToken] Can't fetch access token`);
                this.resumeLogin();
                return;
            }

            try {
                const json = JSON.parse(response);

                if (json.access_token) {
                    this.accessToken = json.access_token;
                    Logger.debug(`[${this.name}::refreshToAccessToken] Get access token`);
                }
            } catch (error: any) {
                Logger.errorThrow(error);
            }

            this.resumeLogin();
        });
    }

    /** Calling PerformLoginFlow with isPerformingLogin = true to proceed login */
    private resumeLogin(): void {
        if (!this.args) return;
        this.isPerformingLogin = true;
        this.args[0].method("PerformLoginFlow", 1).invoke(this.args[1]);
        this.args = undefined;
    }

    /** Checks on 3 parts and shows login toast if valid */
    private validateToken(refreshToken: string): boolean {
        const parts = refreshToken.split(".");
        if (parts.length !== 3) {
            Logger.warn(`[${this.name}::validateToken] Invalid token format (parts: ${parts.length})`);
            Logger.toast(I18n.t("network_toasts.invalid_token"));
            return false;
        }

        const payload = TokenLoginModule.decodeBase64Url(parts[1]);
        if (!payload) {
            Logger.warn(`[${this.name}::validateToken] Failed to decode payload`);
            Logger.toast(I18n.t("network_toasts.invalid_token"));
            return false;
        }

        this.showLoginToast(payload);
        return true;
    }

    // since it's jwt we can show profile name. JSON.parse returns any, so we accepting any here
    private showLoginToast(payload: any): void {
        Logger.toast(I18n.t("network_toasts.logined_in", payload.dn));
        return;
    }

    /**
     * Simple functiont to decode base64url
     *
     * @returns Result is json parsed
     */
    public static decodeBase64Url(base64Url: string): any {
        try {
            let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
            while (base64.length % 4) base64 += "=";

            const base64decoded = Buffer.from(base64, "base64").toString("utf-8");
            return JSON.parse(base64decoded);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }
}
