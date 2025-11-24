import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { Config } from "../data/config.js";
import { Logger } from "../utils/logger.js";

export class GraphicsModule extends BaseModule {
    public name = "Graphics Module";

    // Classes and Instances
    private GraphicsSettings!: Il2Cpp.Class;
    private GraphicsSettingsInstance?: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.ValueType;
    private PlayerInfoHUDBase!: Il2Cpp.Class;
    private Camera!: Il2Cpp.Class;
    private CameraInstance?: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.ValueType;

    // Methods
    private get_TargetFrameRate!: Il2Cpp.Method;
    private set_TargetFrameRate!: Il2Cpp.Method;
    private get_ResolutionScale!: Il2Cpp.Method;
    private set_ResolutionScale!: Il2Cpp.Method;

    private get_ShowNames!: Il2Cpp.Method;
    private SetShowPlayerNamesByDefault!: Il2Cpp.Method;

    private set_fieldOfView!: Il2Cpp.Method;

    public init(): void {
        this.GraphicsSettings = AssemblyHelper.MTFGClient.class("FGClient.GraphicsSettings");
        this.PlayerInfoHUDBase = AssemblyHelper.MTFGClient.class("FGClient.PlayerInfoHUDBase");
        this.Camera = AssemblyHelper.CoreModule.class("UnityEngine.Camera");

        this.get_TargetFrameRate = this.GraphicsSettings.method<number>("get_TargetFrameRate");
        this.set_TargetFrameRate = this.GraphicsSettings.method("set_TargetFrameRate", 1);
        this.get_ResolutionScale = this.GraphicsSettings.method<number>("get_ResolutionScale");
        this.set_ResolutionScale = this.GraphicsSettings.method("set_ResolutionScale", 1);

        this.get_ShowNames = this.PlayerInfoHUDBase.method<boolean>("get_ShowNames");
        this.SetShowPlayerNamesByDefault = this.PlayerInfoHUDBase.method("SetShowPlayerNamesByDefault", 1);

        this.set_fieldOfView = this.Camera.method("set_fieldOfView", 1);
    }

    public override onEnable(): void {
        const module = this;

        this.get_TargetFrameRate.implementation = function (): number {
            Logger.hook("get_TargetFrameRate called");
            return 1337; // litterally unlimited, because it's linked to the screen refresh rate
        };

        this.set_TargetFrameRate.implementation = function (fps) {
            Logger.hook("set_TargetFrameRate called with args:", fps);
            return this.method("set_TargetFrameRate", 1).invoke(1337);
        };

        this.get_ResolutionScale.implementation = function (): number {
            Logger.hook("get_ResolutionScale called");
            module.GraphicsSettingsInstance = this;
            return Config.CustomValues.ResolutionScale;
        };

        this.set_ResolutionScale.implementation = function (scale) {
            Logger.hook("set_ResolutionScale called with args:", scale);
            return this.method("set_ResolutionScale", 1).invoke(Config.CustomValues.ResolutionScale);
        };

        this.set_fieldOfView.implementation = function (value) {
            module.CameraInstance = this;
            if (Config.Toggles.toggleCustomFov) {
                value = Config.CustomValues.FOV;
            }
            return this.method("set_fieldOfView", 1).invoke(value);
        };
    }

    public changeResolutionScale(): void {
        try {
            if (!this.GraphicsSettingsInstance) {
                return;
            }

            Logger.debug("Changing resolution scale to:", Config.CustomValues.ResolutionScale);
            this.GraphicsSettingsInstance.method("set_ResolutionScale", 1).invoke(Config.CustomValues.ResolutionScale);
            /*
            i wanted to make this value changeable in the game, but unfortunately 
            calling ResolutionScaling::UpdateResolutionScaleStatus() just crashes the game for now.
            */
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    /**
     * Wrapper over PlayerInfoHUDBase::SetShowPlayerNamesByDefault()
     *
     * Reads state from PlayerInfoHUDBase::get_ShowNames
     */
    public toggleNames(): void {
        const shouldShowPlayerNames = this.get_ShowNames.invoke() as boolean;
        this.SetShowPlayerNamesByDefault.invoke(!shouldShowPlayerNames);
    }

    /** Wrapper over Config.CustomValues.FOV */
    public changeFOV(value: number): void {
        if (this.CameraInstance) {
            Config.CustomValues.FOV = value;
            //this.CameraInstance.method("set_fieldOfView", 1).invoke(value);
        }
    }
}
