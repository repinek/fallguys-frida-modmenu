import { Rigidbody } from "../../engine/wrappers/Rigidbody";
import { MotorFunctionJump } from "./FG.Common/Character/MotorFunctionJump";
import { CharacterControllerData } from "./FG.Common/CharacterControllerData";

export class FallGuysCharacterController extends Il2Cpp.Object {
    get data(): CharacterControllerData {
        return new CharacterControllerData(this.method<Il2Cpp.Object>("get_Data").invoke());
    }

    get jumpMotorFunction(): MotorFunctionJump {
        return new MotorFunctionJump(this.method<Il2Cpp.Object>("get_JumpMotorFunction").invoke());
    }

    get rigidBody(): Rigidbody {
        return new Rigidbody(this.method<Il2Cpp.Object>("get_RigidBody").invoke());
    }
}
