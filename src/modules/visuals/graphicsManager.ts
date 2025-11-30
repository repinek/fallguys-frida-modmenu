import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { ModSettings } from "../../data/modSettings.js";
import { Logger } from "../../logger/logger.js";

export class GraphicsManagerModule extends BaseModule {
    public readonly name = "GraphicsManager";

    // Classes and Instances
    private GraphicsSettings!: Il2Cpp.Class;
    private GraphicsSettingsInstance?: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.ValueType;
    private PlayerInfoHUDBase!: Il2Cpp.Class;
    private Camera!: Il2Cpp.Class;

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
        this.set_TargetFrameRate = this.GraphicsSettings.method<void>("set_TargetFrameRate", 1);
        this.get_ResolutionScale = this.GraphicsSettings.method<number>("get_ResolutionScale");
        this.set_ResolutionScale = this.GraphicsSettings.method<void>("set_ResolutionScale", 1);

        this.get_ShowNames = this.PlayerInfoHUDBase.method<boolean>("get_ShowNames");
        this.SetShowPlayerNamesByDefault = this.PlayerInfoHUDBase.method<void>("SetShowPlayerNamesByDefault", 1);

        this.set_fieldOfView = this.Camera.method("set_fieldOfView", 1);
    }

    public override initHooks(): void {
        const module = this;

        this.get_TargetFrameRate.implementation = function (): number {
            Logger.hook("get_TargetFrameRate called");
            return 1337; // litterally unlimited, because it's linked to the screen refresh rate (you can't set -1 btw)
        };

        this.set_TargetFrameRate.implementation = function (fps): void {
            Logger.hook("set_TargetFrameRate called with args:", fps);
            return this.method<void>("set_TargetFrameRate", 1).invoke(1337);
        };

        this.get_ResolutionScale.implementation = function (): number {
            Logger.hook("get_ResolutionScale called");
            module.GraphicsSettingsInstance = this;
            return ModSettings.resolutionScale;
        };

        this.set_ResolutionScale.implementation = function (scale): void {
            Logger.hook("set_ResolutionScale called with args:", scale);
            return this.method<void>("set_ResolutionScale", 1).invoke(ModSettings.resolutionScale);
        };

        this.set_fieldOfView.implementation = function (value): void {
            if (ModSettings.customFov) {
                value = ModSettings.fov;
            }
            return this.method<void>("set_fieldOfView", 1).invoke(value);
        };
    }

    public changeResolutionScale(): void {
        try {
            if (!this.GraphicsSettingsInstance) {
                return;
            }

            Logger.debug("Changing resolution scale to:", ModSettings.resolutionScale);
            this.GraphicsSettingsInstance.method("set_ResolutionScale", 1).invoke(ModSettings.resolutionScale);
            /*
            i wanted to make this value changeable in the game, but unfortunately 
            calling ResolutionScaling::UpdateResolutionScaleStatus() just crashes the game for now.
            UPD: IS IT CUZ WRONG THREAD?
            */
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    /**
     * Wrapper over PlayerInfoHUDBase::SetShowPlayerNamesByDefault
     *
     * Reads state from PlayerInfoHUDBase::get_ShowNames
     */
    public toggleNames(): void {
        const shouldShowPlayerNames = this.get_ShowNames.invoke() as boolean;
        this.SetShowPlayerNamesByDefault.invoke(!shouldShowPlayerNames);
    }
}
