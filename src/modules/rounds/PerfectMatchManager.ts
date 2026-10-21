import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { ModSettings } from "../../data/ModSettings";

export class PerfectMatchManagerModule extends BaseModule {
    public readonly name = "PerfectMatchManager";

    // Classes
    private MatchFallTile!: Il2Cpp.Class;

    // Methods
    private Update!: Il2Cpp.Method;

    public init(): void {
        this.MatchFallTile = AssemblyHelper.TheMultiplayerGuys.class("Levels.MatchFall.MatchFallTile");

        this.Update = this.MatchFallTile.method<void>("Update");
    }

    public override initHooks(): void {
        this.Update.implementation = function (): void {
            if (ModSettings.showPerfectMatchTiles) {
                const tileSurfaceOffObject = this.method<Il2Cpp.Object>("get__tileSurfaceOffObject").invoke();
                const tileSurfaceOnObject = this.method<Il2Cpp.Object>("get__tileSurfaceOnObject").invoke();

                tileSurfaceOffObject.method<void>("SetActive").invoke(false);
                tileSurfaceOnObject.method<void>("SetActive").invoke(true);
            }

            this.method<void>("Update").invoke();
        };
    }
}
