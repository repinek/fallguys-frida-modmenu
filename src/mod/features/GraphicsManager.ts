import { AssemblyHelper } from "../../engine/AssemblyHelper";
import { Logger } from "../../utils/Logger";
import { ModSettings } from "../data/ModSettings";

export class GraphicsManager {
    private static GraphicsSettingsInstance: Il2Cpp.Class | Il2Cpp.Object | Il2Cpp.ValueType;

    private static get_ShowNames: Il2Cpp.Method;
    private static SetShowPlayerNamesByDefault: Il2Cpp.Method;

    static init(): void {
        const GraphicsSettings = AssemblyHelper.MTFGClient.class("FGClient.GraphicsSettings");
        const Camera = AssemblyHelper.CoreModule.class("UnityEngine.Camera");

        // What a nightmare, but it's the only valid option here
        GraphicsSettings.method<number>("get_TargetFrameRate").implementation = this.getFramerateHook;
        // @ts-ignore
        GraphicsSettings.method<void>("set_TargetFrameRate", 1).implementation = this.setFramerateHook;
        // @ts-ignore
        GraphicsSettings.method<number>("get_ResolutionScale").implementation = this.getResolutionHook;
        // @ts-ignore
        GraphicsSettings.method<void>("set_ResolutionScale", 1).implementation = this.setResolutionHook;
        // @ts-ignore
        Camera.method("set_fieldOfView", 1).implementation = this.setFovHook;

        const PlayerInfoHUDBase = AssemblyHelper.MTFGClient.class("FGClient.PlayerInfoHUDBase");
        this.get_ShowNames = PlayerInfoHUDBase.method<boolean>("get_ShowNames");
        this.SetShowPlayerNamesByDefault = PlayerInfoHUDBase.method<void>("SetShowPlayerNamesByDefault", 1);

        Logger.info("[GraphicsManager::init] Initialized");
    }

    private static getFramerateHook(): number {
        Logger.hook("get_TargetFrameRate called");
        return 1337; // litterally unlimited, because it's linked to the screen refresh rate (you can't set -1 or 0)
    }

    private static setFramerateHook(this: Il2Cpp.Object, fps: number): void {
        Logger.hook("set_TargetFrameRate called with args:", fps);
        return this.method<void>("set_TargetFrameRate", 1).invoke(1337);
    }

    private static getResolutionHook(this: Il2Cpp.Object): number {
        Logger.hook("get_ResolutionScale called");
        GraphicsManager.GraphicsSettingsInstance = this;
        return ModSettings.resolutionScale;
    }

    private static setResolutionHook(this: Il2Cpp.Object, scale: number): void {
        Logger.hook("set_ResolutionScale called with args:", scale);
        return this.method<void>("set_ResolutionScale", 1).invoke(ModSettings.resolutionScale);
    }

    private static setFovHook(this: Il2Cpp.Object, value: number): void {
        if (ModSettings.customFov) {
            value = ModSettings.fov;
        }
        return this.method<void>("set_fieldOfView", 1).invoke(value);
    }

    static changeResolutionScale(): void {
        if (!this.GraphicsSettingsInstance) {
            return;
        }

        /*
        i wanted to make this value changeable in the game, but unfortunately
        calling ResolutionScaling::UpdateResolutionScaleStatus() just crashes the game for now.
        UPD: IS IT CUZ WRONG THREAD?
        */
        Logger.debug("Changing resolution scale to:", ModSettings.resolutionScale);
        this.GraphicsSettingsInstance.method("set_ResolutionScale", 1).invoke(ModSettings.resolutionScale);
    }

    /**
     * Wrapper over PlayerInfoHUDBase::SetShowPlayerNamesByDefault
     *
     * Reads state from PlayerInfoHUDBase::get_ShowNames
     */
    static toggleNames(): void {
        const shouldShowPlayerNames = this.get_ShowNames.invoke() as boolean;
        this.SetShowPlayerNamesByDefault.invoke(!shouldShowPlayerNames);
    }
}
