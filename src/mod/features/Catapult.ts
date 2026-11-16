import Java from "frida-java-bridge";
import { sharedPreferences } from "frida-java-menu";

import { AssemblyHelper } from "../../engine/AssemblyHelper";
import { UnityUtils } from "../../engine/UnityUtils";
import { JavaUtils } from "../../utils/JavaUtils";
import { Logger } from "../../utils/Logger";
import { Constants } from "../data/Constants";
import { I18n } from "../i18n/I18n";

/*
 * 1. Login and Version Spoofing:
 *    - Overrides clientVersion and clientVersionSignature to match the latest client
 *    - Allows connecting with outdated APKs, data fetched from Constants.SPOOF_VERSION_MIRRORS (thx floyzi) (You can find it yourself if you want)
 *
 * 2. Platform Spoofing:
 *    - We can also change the platform here, but make sure it exists (otherwise you won't be able to login, mediatonic fixed this)
 *      Some existing platforms:
 *      ps5, ps4,
 *      pc_steam, pc_standalone (no longer used for official clients), pc_egs, win (no longer used too)
 *      ports3_2 (3_1) (testing platform for mobile devices)...
 *      android_ega, ios_ega
 *
 * 3. Custom Analytics server:
 *    - We hooks constructor of WebSocketNetworkHost, since we can't modify isSecure in CatapultAnalyticsService::Init_ClientOnly
 * 	  - public void Init_ClientOnly(ServicesEnvironment.Server serverAddress, CatapultGatewayConnection.Config gatewayConnConfig, string platformServiceProvider) {
 *          // ...blablabla
 *			WebSocketNetworkHost networkHost = new WebSocketNetworkHost(serverAddress.Address, serverAddress.Port, true);
 *          // ...blablabla
 *          this._Init(config, sender);
 *      }
 */

interface IClientDetails {
    clientVersion: string;
    clientVersionSignature: string;
}

export class Catapult {
    // any pc platform for some reason on mobile version required EAC_MESSAGE, which we can't handle -> gets disconnected
    static readonly PLATFORMS: string[] = ["android_ega", "ios_ega", "ps5", "xb1", "switch", "ports3_2"];

    private static clientDetails?: IClientDetails;
    private static targetPlatform: string = "android_ega";

    static init(): void {
        // Classes
        const CatapultServicesManager = AssemblyHelper.MTFGClient.class("FGClient.CatapultServices.CatapultServicesManager");
        const WebSocketNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.WebSocketNetworkHost");

        this.fetchClientDetails();
        this.readPlatform();

        //@ts-ignore
        CatapultServicesManager.method<Il2Cpp.Object>("BuildCatapultConfig").implementation = this.buildCatapultConfigHook;
        //@ts-ignore
        WebSocketNetworkHost.method<void>(".ctor", 3).implementation = this.webSocketNetworkHostCtorHook;

        Logger.info("[Catapult::init] Initialized");
    }

    private static buildCatapultConfigHook(this: Il2Cpp.Object): Il2Cpp.Object {
        Logger.hook("BuildCatapultConfig called");
        const catapultConfig = this.method<Il2Cpp.Object>("BuildCatapultConfig").invoke(); // <--- OnLeave

        if (Constants.USE_SPOOF && Catapult.clientDetails) {
            catapultConfig.field<Il2Cpp.String>("ClientVersion").value = Il2Cpp.string(Catapult.clientDetails.clientVersion);
            catapultConfig.field<Il2Cpp.String>("ClientVersionSignature").value = Il2Cpp.string(Catapult.clientDetails.clientVersionSignature);
            Logger.debug(`[${Catapult.name}::BuildCatapultConfig] Applied version spoof to ${Catapult.clientDetails.clientVersion}`);
        }

        if (Catapult.targetPlatform == "android_ega") {
            catapultConfig.field<Il2Cpp.String>("Platform").value = Il2Cpp.string(Catapult.targetPlatform);
            Logger.debug(`[${Catapult.name}::BuildCatapultConfig] Modified platform to ${Catapult.targetPlatform}`);
        }

        if (Constants.USE_CUSTOM_SERVER) {
            const HttpNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.HttpNetworkHost");
            const WebSocketNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.WebSocketNetworkHost");
            const LoginServerHost = UnityUtils.createInstance(HttpNetworkHost, Il2Cpp.string(Constants.CUSTOM_LOGIN_URL), Constants.CUSTOM_LOGIN_PORT);
            const GatewayServerHost = UnityUtils.createInstance(
                WebSocketNetworkHost,
                Il2Cpp.string(Constants.CUSTOM_GATEWAY_URL),
                Constants.CUSTOM_GATEWAY_PORT,
                Constants.IS_GATEWAY_SECURE
            );

            catapultConfig.field("LoginServerHost").value = LoginServerHost;
            catapultConfig.field("GatewayServerHost").value = GatewayServerHost;
            Logger.debug(
                `[${Catapult.name}::BuildCatapultConfig] Applied custom login and gateway server to ${Constants.CUSTOM_LOGIN_URL}, ${Constants.CUSTOM_GATEWAY_URL}`
            );
        }

        return catapultConfig;
    }

    private static webSocketNetworkHostCtorHook(this: Il2Cpp.Object, serverAddress: Il2Cpp.String, port: number, isSecure: boolean): void {
        Logger.hook("WebSocketNetworkHost::.ctor called with args:", serverAddress, port, isSecure);

        if (Constants.USE_CUSTOM_SERVER) {
            if (serverAddress.content === "analytics-gateway.fallguys.oncatapult.com") {
                serverAddress = Il2Cpp.string(Constants.CUSTOM_ANALYTICS_URL);
                port = Constants.CUSTOM_ANALYTICS_PORT;
                isSecure = Constants.IS_ANALYTICS_SECURE;

                Logger.debug(`[${Catapult.name}] Applied custom analytics server to ${Constants.CUSTOM_ANALYTICS_URL}`);
            }
        }

        return this.method<void>(".ctor", 3).invoke(serverAddress, port, isSecure);
    }

    private static fetchClientDetails(): void {
        if (!Constants.USE_SPOOF) {
            return;
        }

        this.tryFetchSpoofData(0);
    }

    private static tryFetchSpoofData(index: number): void {
        const sources = [Constants.SPOOF_VERSION_URL, ...Constants.SPOOF_VERSION_MIRRORS];

        if (index >= sources.length) {
            Logger.warn(`[${this.name}::fetchClientDetails] All mirrors failed, spoof won't be working`);
            Logger.toast(I18n.t("network_toasts.signature_fetch_fail"), 1);
            return;
        }

        const mirror = sources[index];
        Logger.debug(`[${this.name}::fetchClientDetails] Fetching spoof data from ${mirror}`);

        JavaUtils.httpGet(mirror, response => {
            if (!response) {
                this.tryFetchSpoofData(index + 1);
                return;
            }

            try {
                const clientDetails = JSON.parse(response!) as unknown;

                if (!this.isClientDetails(clientDetails)) {
                    Logger.warn(`[${this.name}::fetchClientDetails] Invalid response from ${mirror}, trying next mirror`);
                    this.tryFetchSpoofData(index + 1);
                    return;
                }

                this.clientDetails = clientDetails as IClientDetails;
            } catch {
                Logger.warn(`[${this.name}::fetchClientDetails] Bad response from ${mirror}, trying next mirror`);
                this.tryFetchSpoofData(index + 1);
            }
        });
    }

    private static isClientDetails(value: unknown): value is IClientDetails {
        if (!value || typeof value !== "object") return false;

        const details = value as Record<string, unknown>;
        return (
            typeof details.clientVersion === "string" &&
            details.clientVersion.trim().length > 0 &&
            typeof details.clientVersionSignature === "string" &&
            details.clientVersionSignature.trim().length > 0
        );
    }

    private static readPlatform(): void {
        Java.perform(() => {
            if (sharedPreferences.contains("platform")) {
                this.targetPlatform = sharedPreferences.getString("platform");
            }
        });
    }

    static changePlatform(newPlatform: string): void {
        Java.perform(() => {
            Logger.debug(`put platform string into config: ${newPlatform}`);
            sharedPreferences.putString("platform", newPlatform);
        });
    }

    static getLocalisedPlatforms(): string[] {
        return this.PLATFORMS.map(platform => {
            return I18n.t(`platforms.${platform}`);
        });
    }
}
