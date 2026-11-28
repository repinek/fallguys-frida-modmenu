import { FallGuysCharacterController } from "../../fallguys/wrappers/FallGuysCharacterController";
import { GlobalGameStateClient } from "../../fallguys/wrappers/FGClient/GlobalGameStateClient";

/** Shorthand access to useful in-game properties */
export class InGameUtils {
    /** gameStateView.isGamePlaying and localCharacter exist */
    static isPlayingAndCharacterExist(): boolean {
        const ggsc = GlobalGameStateClient.instance;
        return !!(ggsc?.gameStateView.isGamePlaying && ggsc.playerManager.localCharacter)
    }

    static get localCharacter(): FallGuysCharacterController | undefined {
        return GlobalGameStateClient.instance?.playerManager.localCharacter;
    }
}
