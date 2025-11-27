import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { Config } from "../data/config.js";
import { Logger } from "../logger/logger.js";
import * as JavaUtils from "../utils/javaUtils.js";

interface IClientDetails {
    clientVersion: string;
    clientVersionSignature: string;
}

export class CatapultModule extends BaseModule {
    public name = "Catapult";

    // Classes
    private CatapultServicesManager!: Il2Cpp.Class;

    private HttpNetworkHost!: Il2Cpp.Class;
    private WebSocketNetworkHost!: Il2Cpp.Class;

    // Methods
    private BuildCatapultConfig!: Il2Cpp.Method;

    private WebSocketNetworkHostCtor!: Il2Cpp.Method;

    private clientDetails: IClientDetails | null = null;

    public init(): void {
        this.CatapultServicesManager = AssemblyHelper.MTFGClient.class("FGClient.CatapultServices.CatapultServicesManager");

        this.HttpNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.HttpNetworkHost");
        this.WebSocketNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.WebSocketNetworkHost");

        this.BuildCatapultConfig = this.CatapultServicesManager.method<Il2Cpp.Object>("BuildCatapultConfig");
        this.WebSocketNetworkHostCtor = this.WebSocketNetworkHost.method<void>(".ctor", 3);

        this.fetchClientDetails();
    }

    public override onEnable(): void {
        const module = this;

        this.BuildCatapultConfig.implementation = function (): Il2Cpp.Object {
            Logger.hook("BuildCatapultConfig called");

            const catapultConfig = this.method<Il2Cpp.Object>("BuildCatapultConfig").invoke(); // <--- OnLeave

            if (Config.USE_SPOOF && module.clientDetails) {
                catapultConfig.field<Il2Cpp.String>("ClientVersion").value = Il2Cpp.string(module.clientDetails.clientVersion);
                catapultConfig.field<Il2Cpp.String>("ClientVersionSignature").value = Il2Cpp.string(module.clientDetails.clientVersionSignature);
                Logger.debug(`[${module.name}] Applied version spoof to ${module.clientDetails.clientVersion}`);
            }

            if (Config.BuildInfo.PLATFORM != "android_ega") {
                catapultConfig.field<Il2Cpp.String>("Platform").value = Il2Cpp.string(Config.BuildInfo.PLATFORM);
                Logger.debug(`[${module.name}] Modified platform to ${Config.BuildInfo.PLATFORM}`);
            }

            if (Config.USE_CUSTOM_SERVER) {
                const LoginServerHost = module.HttpNetworkHost.alloc();
                const GatewayServerHost = module.WebSocketNetworkHost.alloc();

                LoginServerHost.method(".ctor").invoke(Il2Cpp.string(Config.CUSTOM_LOGIN_URL), Config.CUSTOM_LOGIN_PORT);
                GatewayServerHost.method(".ctor").invoke(Il2Cpp.string(Config.CUSTOM_GATEWAY_URL), Config.CUSTOM_GATEWAY_PORT, Config.IS_GATEWAY_SECURE);

                catapultConfig.field("LoginServerHost").value = LoginServerHost;
                catapultConfig.field("GatewayServerHost").value = GatewayServerHost;
                Logger.debug(`[${module.name}] Applied custom login and gateway server to ${Config.CUSTOM_LOGIN_URL}, ${Config.CUSTOM_GATEWAY_URL}`);
            }

            return catapultConfig;
        };

        //@ts-ignore
        this.WebSocketNetworkHostCtor.implementation = function (serverAddress: Il2Cpp.String, port: number, isSecure: boolean): void {
            Logger.hook("WebSocketNetworkHost::.ctor called with args:", serverAddress, port, isSecure);

            if (Config.USE_CUSTOM_SERVER) {
                if (serverAddress.content == "analytics-gateway.fallguys.oncatapult.com") {
                    serverAddress = Il2Cpp.string(Config.CUSTOM_ANALYTICS_URL);
                    port = Config.CUSTOM_ANALYTICS_PORT;
                    isSecure = Config.IS_ANALYTICS_SECURE;

                    Logger.debug(`[${module.name}] Applied custom analytics server to ${Config.CUSTOM_ANALYTICS_URL}`);
                }
            }

            return this.method<void>(".ctor", 3).invoke(serverAddress, port, isSecure);
        };
    }

    private fetchClientDetails() {
        if (Config.USE_SPOOF) {
            JavaUtils.httpGet(Config.SPOOF_VERSION_URL, response => {
                if (!response) {
                    Logger.warn(`[${this.name}::fetchSpoofData] Actual server signature can't be fetched, spoof won't be working`);
                    //Menu.toast(en.toasts.signature_not_fetched, 1);
                    return;
                }
                this.clientDetails = JSON.parse(response) as IClientDetails;
            });
        }
    }
}
