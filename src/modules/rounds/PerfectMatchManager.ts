import { AssemblyHelper } from "../../core/AssemblyHelper";
import { ModSettings } from "../../data/ModSettings";
import { Logger } from "../../logger/Logger";

export class PerfectMatchManager {
    static init(): void {
        // Classes
        const MatchFallTile = AssemblyHelper.TheMultiplayerGuys.class("Levels.MatchFall.MatchFallTile");

        // Methods
        //@ts-ignore
        MatchFallTile.method<void>("Update").implementation = this.updateHook;

        Logger.info("[PerfectMatchManager::init] Initialized");
    }

    private static updateHook(this: Il2Cpp.Object): void {
        if (ModSettings.showPerfectMatchTiles) {
            const tileSurfaceOffObject = this.method<Il2Cpp.Object>("get__tileSurfaceOffObject").invoke();
            const tileSurfaceOnObject = this.method<Il2Cpp.Object>("get__tileSurfaceOnObject").invoke();

            tileSurfaceOffObject.method<void>("SetActive").invoke(false);
            tileSurfaceOnObject.method<void>("SetActive").invoke(true);
        }

        this.method<void>("Update").invoke();
    }
}
