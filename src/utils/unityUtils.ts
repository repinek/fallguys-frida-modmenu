import "frida-il2cpp-bridge";

import { Logger } from "./logger.js";
import { Config } from "../data/config.js";

// TODO: move findobjectstypeof here
export function teleportTo(playerInstance: Il2Cpp.Object, targetInstance: Il2Cpp.Object): void {
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

export class TeleportManager {
    private static lastTeleportTime = 0;

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
}
