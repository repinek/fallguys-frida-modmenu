import { AssemblyHelper } from "../../core/AssemblyHelper";

import { GameDefaults } from "../../data/GameDefaults";
import { ModSettings } from "../../data/ModSettings";
import { Logger } from "../../logger/Logger";

/*
 * Original CharacterDataMonitor::CheckCharacterControllerData logic is
 *    - called by update func
 *    - generates checksum from character.data
 *    - compares with hardcoded hash
 *    - if checksum != hardcoded hash -> return false
 *    if false:
 *    SwitchToDisconnectingState(reason.IngameMenuLeaveMatch)
 *
 * character arg is our FallGuysCharacterController,
 * so we can easily grab it and change values as we want (but we force returning true)
 */

export class CharacterPhysics {
    // Classes and Instances
    private static character?: Il2Cpp.Object; // FallGuysCharacterController
    static _character?: Il2Cpp.Object;

    static init(): void {
        const CharacterDataMonitor = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
        const MotorFunctionJump = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.Character.MotorFunctionJump");
        const MPGNetMotorTasks = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.MPGNetMotorTasks");

        // Methods
        // Boolean CheckCharacterControllerData(FallGuysCharacterController character*)
        //@ts-ignore
        CharacterDataMonitor.method<boolean>("CheckCharacterControllerData", 1).implementation = this.checkCharacterControllerDataHook;
        //@ts-ignore
        MotorFunctionJump.method<boolean>("CanJump").implementation = this.canJumpHook;
        //@ts-ignore
        MPGNetMotorTasks.method<void>("SendMessage", 1).implementation = this.sendMessageHook;

        Logger.info("[CharacterPhysics::init] Initialized");
    }

    private static checkCharacterControllerDataHook(character: Il2Cpp.Object): boolean {
        CharacterPhysics.character = character; // Instance of class FallGuysCharacterController
        CharacterPhysics._character = character;

        const data = character.method<Il2Cpp.Object>("get_Data").invoke(); // Instance of class CharacterControllerData
        const jumpMotor = character.method<Il2Cpp.Object>("get_JumpMotorFunction").invoke(); // Instance of class MotorFunctionJump

        CharacterPhysics.changeSpeed(data);
        CharacterPhysics.changeGravity(data);
        CharacterPhysics.changeDive(data);
        CharacterPhysics.changeJump(jumpMotor);

        return true;
    }

    private static canJumpHook(this: Il2Cpp.Object): boolean {
        if (ModSettings.airjump) {
            return true;
        }
        return this.method<boolean>("CanJump").invoke();
    }

    private static sendMessageHook(this: Il2Cpp.Object, bypassNetworkLOD: boolean): void {
        if (ModSettings.dontSendFallGuyState) {
            return;
        }
        return this.method<void>("SendMessage", 1).invoke(bypassNetworkLOD);
    }

    private static changeSpeed(data: Il2Cpp.Object): void {
        const speed = ModSettings.customSpeed ? ModSettings.normalMaxSpeed : GameDefaults.normalMaxSpeed;

        data.field("normalMaxSpeed").value = speed;
        data.field("carryMaxSpeed").value = speed;
        data.field("grabbingMaxSpeed").value = speed;
    }

    private static changeGravity(data: Il2Cpp.Object): void {
        let gravity: number = GameDefaults.maxGravityVelocity;

        if (ModSettings.customGravity) {
            if (ModSettings.noGravity) {
                gravity = 0;
            } else if (ModSettings.negativeGravity) {
                gravity = -ModSettings.maxGravityVelocity;
            } else {
                gravity = ModSettings.maxGravityVelocity;
            }
        }

        data.field("maxGravityVelocity").value = gravity;
    }

    private static changeDive(data: Il2Cpp.Object): void {
        const diveSensitivity = ModSettings.enable360Dives ? 69420 : GameDefaults.divePlayerSensitivity;

        data.field("divePlayerSensitivity").value = diveSensitivity;

        if (ModSettings.customDiveForce) {
            data.field("diveForce").value = ModSettings.diveForce;
            data.field("airDiveForce").value = ModSettings.diveForce / GameDefaults.diveMultiplier;
        } else {
            data.field("diveForce").value = GameDefaults.diveForce;
            data.field("airDiveForce").value = GameDefaults.airDiveForce;
        }
    }

    private static changeJump(jumpMotor: Il2Cpp.Object): void {
        const targetJump = ModSettings.customJumpForce ? ModSettings.jumpForce : GameDefaults.jumpForce;

        const jumpForce = jumpMotor.field<Il2Cpp.ValueType>("_jumpForce").value;
        jumpForce.field("y").value = targetJump;
    }

    static freezePlayer(state: boolean): void {
        try {
            const characterRigidBody = this.character!.method<Il2Cpp.Object>("get_RigidBody").invoke();
            characterRigidBody.method<void>("set_isKinematic").invoke(state);
        } catch (error: any) {
            Logger.warn(`[${this.name}::freezePlayer] No character Instance found: ${error.name}`);
        }
    }

    static get Character(): Il2Cpp.Object | undefined {
        return this._character;
    }
}
