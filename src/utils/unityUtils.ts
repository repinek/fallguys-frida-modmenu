import { AssemblyHelper } from "../core/assemblyHelper.js";
import { Logger } from "./logger.js";
import { Config } from "../data/config.js";

export class UnityUtils {
    private static Resources: Il2Cpp.Class;

    public static init() {
        this.Resources = AssemblyHelper.CoreModule.class("UnityEngine.Resources");
        Logger.info("[UnityUtils] Initialized");
    }

    /** Wrapper over `UnityEngine.Resources.FindObjectsOfTypeAll` */
    public static findObjectsOfTypeAll(klass: Il2Cpp.Class): Il2Cpp.Array<Il2Cpp.Object> {
        return this.Resources.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1).invoke(klass.type.object);
    }
}

export class TeleportManager {
    private static lastTeleportTime = 0;

    /**
     * Behavior:
     * - if false: Shows toast with time you need to wait
     *
     * @returns `true` if allowed, `false` if on cooldown
     */
    public static checkCooldown(): boolean {
        const currentTime = Date.now();
        const diff = currentTime - this.lastTeleportTime;

        if (diff < Config.TELEPORT_COOLDOWN) {
            const remaining = ((Config.TELEPORT_COOLDOWN - diff) / 1000).toFixed(1);
            Menu.toast(`Wait ${remaining}s`, 0);
            return false;
        }

        this.lastTeleportTime = currentTime;
        return true;
    }

    /**
     * Teleports the player to the target object's position.
     *
     * @param playerInstance The Player Object
     * @param targetInstance The destination Object
     */
    public static teleportTo(playerInstance: Il2Cpp.Object, targetInstance: Il2Cpp.Object): void {
        try {
            // prettier-ignore
            const targetPos = targetInstance
            .method<Il2Cpp.Object>("get_transform").invoke()
            .method<Il2Cpp.Object>("get_position").invoke();

            // prettier-ignore
            playerInstance
            .method<Il2Cpp.Object>("get_transform").invoke()
            .method<Il2Cpp.Object>("set_position").invoke(targetPos);
        } catch (error: any) {
            Logger.errorThrow(error, "Teleport");
        }
    }
}
