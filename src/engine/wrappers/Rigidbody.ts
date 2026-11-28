import { Vector3 } from "./Vector3";

export class Rigidbody extends Il2Cpp.Object {
    set isKinematic(value: boolean) {
        this.method<void>("set_isKinematic").invoke(value);
    }

    set position(value: Vector3) {
        this.method<void>("set_position").invoke(value);
    }
}
