import { FallGuysCharacterController } from "../FallGuysCharacterController";

export class ClientPlayerManager extends Il2Cpp.Object {
    // Actually, a little bit inconsistent with fall guys original code base here, but it's okay
    get localCharacter(): FallGuysCharacterController | undefined {
        const networkPlayerData = this.field<Il2Cpp.Object>("LocalPlayer_ReadOnly").value;
        if (networkPlayerData.isNull()) return undefined;

        return new FallGuysCharacterController(networkPlayerData.field<Il2Cpp.Object>("fgcc").value);
    }
}
