import { StringPrereference } from "../../android/Preference";
import { AssemblyHelper } from "../../engine/AssemblyHelper";
import { UnityUtils } from "../../engine/UnityUtils";
import { UnityWebRequest } from "../../engine/wrappers/UnityWebRequest";
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
 *    - We hooks constructor of WebSocketNetworkHost, since we can't modify isSecure in CatapultAnalyticsService::Init_ClientOnly (or we can? Not sure, but our method is just easier)
 * 	  - public void Init_ClientOnly(ServicesEnvironment.Server serverAddress, CatapultGatewayConnection.Config gatewayConnConfig, string platformServiceProvider) {
 *          // ...blablabla
 *			WebSocketNetworkHost networkHost = new WebSocketNetworkHost(serverAddress.Address, serverAddress.Port, true);
 *          // ...blablabla
 *          this._Init(config, sender);
 *      }
 */

interface ClientDetails {
    clientVersion: string;
    clientVersionSignature: string;
}

export class Catapult {
    // any pc platform for some reason on mobile version required EAC_MESSAGE, which we can't handle -> gets disconnected
    static readonly PLATFORMS: string[] = ["android_ega", "ios_ega", "ps5", "xb1", "switch", "ports3_2"];

    private static clientDetails?: ClientDetails;
    private static targetPlatform: string;

    static readonly platformPreference: StringPrereference = new StringPrereference("platform");

    static init(): void {
        const CatapultServicesManager = AssemblyHelper.MTFGClient.class("FGClient.CatapultServices.CatapultServicesManager");
        const WebSocketNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.WebSocketNetworkHost");

        this.fetchClientDetails();
        // "android_ega" is default platform on android devices
        // so we keep that if nothing written in platformPreference
        this.targetPlatform = this.platformPreference.read() ?? "android_ega";

        //@ts-ignore
        CatapultServicesManager.method<Il2Cpp.Object>("BuildCatapultConfig").implementation = this.buildCatapultConfigHook;
        //@ts-ignore
        WebSocketNetworkHost.method<void>(".ctor", 3).implementation = this.webSocketNetworkHostCtorHook;

        Logger.info("[Catapult::init] Initialized");
    }

    private static buildCatapultConfigHook(this: Il2Cpp.Object): Il2Cpp.Object {
        Logger.hook("BuildCatapultConfig called");
        const catapultConfig = this.method<Il2Cpp.Object>("BuildCatapultConfig").invoke(); // <--- OnLeave

        // Spoof clientDetails
        if (Constants.USE_SPOOF && Catapult.clientDetails) {
            catapultConfig.field<Il2Cpp.String>("ClientVersion").value = Il2Cpp.string(Catapult.clientDetails.clientVersion);
            catapultConfig.field<Il2Cpp.String>("ClientVersionSignature").value = Il2Cpp.string(Catapult.clientDetails.clientVersionSignature);
            Logger.debug(`[Catapult::BuildCatapultConfig] Applied version spoof to ${Catapult.clientDetails.clientVersion}`);
        }

        // Spoof platform
        if (Catapult.targetPlatform !== "android_ega") {
            catapultConfig.field<Il2Cpp.String>("Platform").value = Il2Cpp.string(Catapult.targetPlatform);
            Logger.debug(`[Catapult::BuildCatapultConfig] Modified platform to ${Catapult.targetPlatform}`);
        }

        // Spoof login and gateway server
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
                `[Catapult::BuildCatapultConfig] Applied custom login and gateway server to ${Constants.CUSTOM_LOGIN_URL}, ${Constants.CUSTOM_GATEWAY_URL}`
            );
        }

        return catapultConfig;
    }

    private static webSocketNetworkHostCtorHook(this: Il2Cpp.Object, serverAddress: Il2Cpp.String, port: number, isSecure: boolean): void {
        Logger.hook("WebSocketNetworkHost::.ctor called with args:", serverAddress, port, isSecure);

        // Spoof analytics server
        if (Constants.USE_CUSTOM_SERVER) {
            if (serverAddress.content === "analytics-gateway.fallguys.oncatapult.com") {
                serverAddress = Il2Cpp.string(Constants.CUSTOM_ANALYTICS_URL);
                port = Constants.CUSTOM_ANALYTICS_PORT;
                isSecure = Constants.IS_ANALYTICS_SECURE;

                Logger.debug(`[Catapult] Applied custom analytics server to ${Constants.CUSTOM_ANALYTICS_URL}`);
            }
        }

        return this.method<void>(".ctor", 3).invoke(serverAddress, port, isSecure);
    }

    /** Fetches latest signature and client version for spoof */
    private static async fetchClientDetails(): Promise<void> {
        if (!Constants.USE_SPOOF) return;

        const sources = [Constants.SPOOF_VERSION_URL, ...Constants.SPOOF_VERSION_MIRRORS];

        for (const mirror of sources) {
            Logger.debug(`[Catapult::fetchClientDetails] Fetching spoof data from ${mirror}`);

            let clientDetails: ClientDetails;

            // sendGet will throw error if mirror is dead
            try {
                const request = await UnityWebRequest.sendGet(mirror);
                try {
                    clientDetails = JSON.parse(request.text) as ClientDetails;
                } finally {
                    request.dispose();
                }
            } catch {
                Logger.warn(`[Catapult::fetchClientDetails] Bad response from ${mirror}, trying next mirror`);
                continue;
            }

            if (clientDetails) {
                this.clientDetails = clientDetails;
            }
        }

        Logger.warn(`[Catapult::fetchClientDetails] All mirrors failed, spoof won't be working`);
        Logger.toast(I18n.t("network_toasts.signature_fetch_fail"), 1);
    }
}
