import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { Logger } from "../utils/logger.js";
import { Config } from "../data/config.js";

export class GraphicsModule extends BaseModule {
    public name = "FPSBypass";

    private GraphicsSettings!: Il2Cpp.Class;
    private GraphicsSettings_Instance?: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.ValueType;

    private get_TargetFrameRate!: Il2Cpp.Method;
    private set_TargetFrameRate!: Il2Cpp.Method;

    private get_ResolutionScale!: Il2Cpp.Method;
    private set_ResolutionScale!: Il2Cpp.Method;

    public init(): void {
        this.GraphicsSettings = AssemblyHelper.MTFGClient.class("FGClient.GraphicsSettings");

        this.get_TargetFrameRate = this.GraphicsSettings.method("get_TargetFrameRate");
        this.set_TargetFrameRate = this.GraphicsSettings.method("set_TargetFrameRate", 1);
        this.get_ResolutionScale = this.GraphicsSettings.method("get_ResolutionScale");
        this.set_ResolutionScale = this.GraphicsSettings.method("set_ResolutionScale", 1);

        this.onEnable();
    }

    public override onEnable(): void {
        const module = this;

        this.get_TargetFrameRate.implementation = function () {
            Logger.hook("get_TargetFrameRate called");
            return 1337; // litterally unlimited, because it's linked to the screen refresh rate
        };

        this.set_TargetFrameRate.implementation = function (fps) {
            Logger.hook("set_TargetFrameRate called with args:", fps);
            return this.method("set_TargetFrameRate", 1).invoke(1337);
        };

        this.get_ResolutionScale.implementation = function () {
            Logger.hook("get_ResolutionScale called");
            module.GraphicsSettings_Instance = this;
            return Config.CustomValues.ResolutionScale;
        };

        this.set_ResolutionScale.implementation = function (scale) {
            Logger.hook("set_ResolutionScale called with args:", scale);
            return this.method("set_ResolutionScale", 1).invoke(Config.CustomValues.ResolutionScale);
        };
    }

    public changeResolutionScale(): void {
        try {
            if (!this.GraphicsSettings_Instance) {
                return;
            }

            Logger.debug("Changing resolution scale to:", Config.CustomValues.ResolutionScale);
            this.GraphicsSettings_Instance.method("set_ResolutionScale", 1).invoke(Config.CustomValues.ResolutionScale);
            /*
            i wanted to make this value changeable in the game, but unfortunately 
            calling ResolutionScaling::UpdateResolutionScaleStatus() just crashes the game for now.
            */
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }
}
