import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";

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

export class CharacterPhysicsModule extends BaseModule {
    public readonly name = "CharacterPhysics";

    // Classes and Instances
    private CharacterDataMonitor!: Il2Cpp.Class;
    private MotorFunctionJump!: Il2Cpp.Class;
    private MPGNetMotorTasks!: Il2Cpp.Class;

    private character?: Il2Cpp.Object; // FallGuysCharacterController
    static _character?: Il2Cpp.Object;

    // Methods
    private CheckCharacterControllerData!: Il2Cpp.Method;
    private CanJump!: Il2Cpp.Method;
    private SendMessage!: Il2Cpp.Method;

    public init(): void {
        this.CharacterDataMonitor = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
        this.MotorFunctionJump = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.Character.MotorFunctionJump");
        this.MPGNetMotorTasks = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.MPGNetMotorTasks");

        // Boolean CheckCharacterControllerData(FallGuysCharacterController character*)
        this.CheckCharacterControllerData = this.CharacterDataMonitor.method<boolean>("CheckCharacterControllerData", 1);
        this.CanJump = this.MotorFunctionJump.method<boolean>("CanJump");
        this.SendMessage = this.MPGNetMotorTasks.method<void>("SendMessage", 1);
    }

    public override initHooks(): void {
        const module = this;

        //@ts-ignore
        this.CheckCharacterControllerData.implementation = function (character: Il2Cpp.Object): boolean {
            module.character = character; // Instance of class FallGuysCharacterController
            CharacterPhysicsModule._character = character;

            const data = character.method<Il2Cpp.Object>("get_Data").invoke(); // Instance of class CharacterControllerData
            const jumpMotor = character.method<Il2Cpp.Object>("get_JumpMotorFunction").invoke(); // Instance of class MotorFunctionJump

            module.changeSpeed(data);
            module.changeGravity(data);
            module.changeDive(data);
            module.changeJump(jumpMotor);

            return true;
        };

        this.CanJump.implementation = function (): boolean {
            if (ModSettings.airjump) {
                return true;
            }
            return this.method<boolean>("CanJump").invoke();
        };

        this.SendMessage.implementation = function (bypassNetworkLOD): void {
            if (ModSettings.dontSendFallGuyState) {
                return;
            }
            return this.method<void>("SendMessage", 1).invoke(bypassNetworkLOD);
        };
    }

    private changeSpeed(data: Il2Cpp.Object): void {
        const speed = ModSettings.customSpeed ? ModSettings.normalMaxSpeed : GameDefaults.normalMaxSpeed;

        data.field("normalMaxSpeed").value = speed;
        data.field("carryMaxSpeed").value = speed;
        data.field("grabbingMaxSpeed").value = speed;
    }

    private changeGravity(data: Il2Cpp.Object): void {
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

    private changeDive(data: Il2Cpp.Object): void {
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

    private changeJump(jumpMotor: Il2Cpp.Object): void {
        const targetJump = ModSettings.customJumpForce ? ModSettings.jumpForce : GameDefaults.jumpForce;

        const jumpForce = jumpMotor.field<Il2Cpp.ValueType>("_jumpForce").value;
        jumpForce.field("y").value = targetJump;
    }

    public freezePlayer(state: boolean): void {
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
