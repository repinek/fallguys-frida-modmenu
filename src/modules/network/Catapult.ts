import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { Constants } from "../../data/Constants";
import { I18n } from "../../i18n/I18n";
import { Logger } from "../../logger/Logger";
import { JavaUtils } from "../../utils/JavaUtils";
import { UnityUtils } from "../../utils/UnityUtils";

/*
 * 1. Login and Version Spoofing:
 *    - Overrides clientVersion and clientVersionSignature to match the latest client
 *    - Allows connecting with outdated APKs, data fetched from Constants.VERSION_URL (thx floyzi) (You can find it yourself if you want)
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

export class CatapultModule extends BaseModule {
    public readonly name = "Catapult";

    // any pc platform for some reason on mobile version required EAC_MESSAGE, which we can't handle -> gets disconnected
    static readonly PLATFORMS: string[] = ["android_ega", "ios_ega", "ps5", "xb1", "switch", "ports3_2"];

    // Classes
    private CatapultServicesManager!: Il2Cpp.Class;

    private HttpNetworkHost!: Il2Cpp.Class;
    private WebSocketNetworkHost!: Il2Cpp.Class;

    // Methods
    private BuildCatapultConfig!: Il2Cpp.Method;
    private WebSocketNetworkHostCtor!: Il2Cpp.Method;

    private clientDetails?: IClientDetails;
    private targetPlatform: string = "android_ega";

    public init(): void {
        this.CatapultServicesManager = AssemblyHelper.MTFGClient.class("FGClient.CatapultServices.CatapultServicesManager");

        this.HttpNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.HttpNetworkHost");
        this.WebSocketNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.WebSocketNetworkHost");

        this.BuildCatapultConfig = this.CatapultServicesManager.method<Il2Cpp.Object>("BuildCatapultConfig");
        this.WebSocketNetworkHostCtor = this.WebSocketNetworkHost.method<void>(".ctor", 3);

        this.fetchClientDetails();
        this.readPlatform();
    }

    public override initHooks(): void {
        const module = this;

        this.BuildCatapultConfig.implementation = function (): Il2Cpp.Object {
            Logger.hook("BuildCatapultConfig called");
            const catapultConfig = this.method<Il2Cpp.Object>("BuildCatapultConfig").invoke(); // <--- OnLeave

            if (Constants.USE_SPOOF && module.clientDetails) {
                catapultConfig.field<Il2Cpp.String>("ClientVersion").value = Il2Cpp.string(module.clientDetails.clientVersion);
                catapultConfig.field<Il2Cpp.String>("ClientVersionSignature").value = Il2Cpp.string(module.clientDetails.clientVersionSignature);
                Logger.debug(`[${module.name}::BuildCatapultConfig] Applied version spoof to ${module.clientDetails.clientVersion}`);
            }

            if (module.targetPlatform != "android_ega") {
                catapultConfig.field<Il2Cpp.String>("Platform").value = Il2Cpp.string(module.targetPlatform);
                Logger.debug(`[${module.name}::BuildCatapultConfig] Modified platform to ${module.targetPlatform}`);
            }

            if (Constants.USE_CUSTOM_SERVER) {
                const LoginServerHost = UnityUtils.createInstance(
                    module.HttpNetworkHost,
                    Il2Cpp.string(Constants.CUSTOM_LOGIN_URL),
                    Constants.CUSTOM_LOGIN_PORT
                );
                const GatewayServerHost = UnityUtils.createInstance(
                    module.WebSocketNetworkHost,
                    Il2Cpp.string(Constants.CUSTOM_GATEWAY_URL),
                    Constants.CUSTOM_GATEWAY_PORT,
                    Constants.IS_GATEWAY_SECURE
                );

                catapultConfig.field("LoginServerHost").value = LoginServerHost;
                catapultConfig.field("GatewayServerHost").value = GatewayServerHost;
                Logger.debug(
                    `[${module.name}::BuildCatapultConfig] Applied custom login and gateway server to ${Constants.CUSTOM_LOGIN_URL}, ${Constants.CUSTOM_GATEWAY_URL}`
                );
            }

            return catapultConfig;
        };

        //@ts-ignore
        this.WebSocketNetworkHostCtor.implementation = function (serverAddress: Il2Cpp.String, port: number, isSecure: boolean): void {
            Logger.hook("WebSocketNetworkHost::.ctor called with args:", serverAddress, port, isSecure);

            if (Constants.USE_CUSTOM_SERVER) {
                if (serverAddress.content == "analytics-gateway.fallguys.oncatapult.com") {
                    serverAddress = Il2Cpp.string(Constants.CUSTOM_ANALYTICS_URL);
                    port = Constants.CUSTOM_ANALYTICS_PORT;
                    isSecure = Constants.IS_ANALYTICS_SECURE;

                    Logger.debug(`[${module.name}] Applied custom analytics server to ${Constants.CUSTOM_ANALYTICS_URL}`);
                }
            }

            return this.method<void>(".ctor", 3).invoke(serverAddress, port, isSecure);
        };
    }

    private fetchClientDetails(): void {
        if (Constants.USE_SPOOF) {
            JavaUtils.httpGet(Constants.SPOOF_VERSION_URL, response => {
                if (!response) {
                    Logger.warn(`[${this.name}::fetchSpoofData] Actual server signature can't be fetched, spoof won't be working`);
                    Logger.toast(I18n.t("network_toasts.signature_fetch_fail"), 1);
                    return;
                }
                this.clientDetails = JSON.parse(response) as IClientDetails;
            });
        }
    }

    private readPlatform(): void {
        Java.perform(() => {
            if (Menu.sharedPreferences.contains("platform")) {
                this.targetPlatform = Menu.sharedPreferences.getString("platform");
            }
        });
    }

    static changePlatform(newPlatform: string): void {
        Java.perform(() => {
            Logger.debug(`put platform string into config: ${newPlatform}`);
            Menu.sharedPreferences.putString("platform", newPlatform);
        });
    }

    static getLocalisedPlatforms(): string[] {
        return this.PLATFORMS.map(platform => {
            return I18n.t(`platforms.${platform}`);
        });
    }
}
