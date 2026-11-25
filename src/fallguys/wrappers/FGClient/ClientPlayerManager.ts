import { FallGuysCharacterController } from "../FallGuysCharacterController";

export class ClientPlayerManager extends Il2Cpp.Object {
    // Actually, a little bit inconsistent with fall guys original code base here
    get localPlayer(): FallGuysCharacterController {
        const networkPlayerData = this.method<Il2Cpp.Object>("get_LocalPlayer_ReadOnly").invoke();
        return new FallGuysCharacterController(networkPlayerData.field<Il2Cpp.Object>("get_fgcc").value);
    }
}
