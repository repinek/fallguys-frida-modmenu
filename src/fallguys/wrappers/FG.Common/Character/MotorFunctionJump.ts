import { Vector3 } from "../../../../engine/wrappers/Vector3";

// extends MotorFunction in original
export class MotorFunctionJump extends Il2Cpp.Object {
    get jumpForce(): Vector3 {
        // getter returns a new copy so it's not editable
        // const value = this.method<Il2Cpp.ValueType>("get_JumpForce").invoke();
        const value = this.field<Il2Cpp.ValueType>("_jumpForce").value;
        return new Vector3(value.handle, value.type);
    }
}
