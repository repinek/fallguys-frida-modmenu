import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { GameObject } from "../../../engine/wrappers/GameObject";
import { Logger } from "../../../utils/Logger";
import { ModSettings } from "../../data/ModSettings";

export class PerfectMatchReveal {
    static init(): void {
        const MatchFallTile = AssemblyHelper.TheMultiplayerGuys.class("Levels.MatchFall.MatchFallTile");
        //@ts-ignore
        MatchFallTile.method<void>("Update").implementation = this.updateHook;

        Logger.info("[PerfectMatchManager::init] Initialized");
    }

    private static updateHook(this: Il2Cpp.Object): void {
        if (ModSettings.showPerfectMatchTiles) {
            const tileSurfaceOffObject = new GameObject(this.method<Il2Cpp.Object>("get__tileSurfaceOffObject").invoke());
            const tileSurfaceOnObject = new GameObject(this.method<Il2Cpp.Object>("get__tileSurfaceOnObject").invoke());
            tileSurfaceOffObject.setActive(false);
            tileSurfaceOnObject.setActive(true);
        }

        this.method<void>("Update").invoke();
    }
}
