import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";

import { Config } from "../../data/config.js";
import { Logger } from "../../logger/logger.js";

export class CharacterPhysicsModule extends BaseModule {
    public name = "CharacterPhysics";

    // Classes and Instances
    private CharacterDataMonitor!: Il2Cpp.Class;
    private MotorFunctionJump!: Il2Cpp.Class;
    private MPGNetMotorTasks!: Il2Cpp.Class;

    private character?: Il2Cpp.Object; // FallGuysCharacterController
    public static _character?: Il2Cpp.Object;

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

    public override onEnable(): void {
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
            if (Config.Toggles.toggleAirJump) {
                return true;
            }
            return this.method<boolean>("CanJump").invoke();
        };

        this.SendMessage.implementation = function (bypassNetworkLOD): void {
            if (Config.Toggles.toggleDontSendFallGuyState) {
                return;
            }
            return this.method<void>("SendMessage", 1).invoke(bypassNetworkLOD);
        };
    }

    private changeSpeed(data: Il2Cpp.Object): void {
        const speed = Config.Toggles.toggleCustomSpeed ? Config.CustomValues.normalMaxSpeed : Config.DefaultValues.normalMaxSpeed;

        data.field("normalMaxSpeed").value = speed;
        data.field("carryMaxSpeed").value = speed;
        data.field("grabbingMaxSpeed").value = speed;
    }

    private changeGravity(data: Il2Cpp.Object): void {
        let gravity = Config.DefaultValues.maxGravityVelocity;

        if (Config.Toggles.toggleCustomVelocity) {
            if (Config.Toggles.toggleNoVelocity) {
                gravity = 0;
            } else if (Config.Toggles.toggleNegativeVelocity) {
                gravity = -Config.CustomValues.maxGravityVelocity;
            } else {
                gravity = Config.CustomValues.maxGravityVelocity;
            }
        }

        data.field("maxGravityVelocity").value = gravity;
    }

    private changeDive(data: Il2Cpp.Object): void {
        const diveSensitivity = Config.Toggles.toggle360Dives ? 69420 : Config.DefaultValues.divePlayerSensitivity;

        data.field("divePlayerSensitivity").value = diveSensitivity;

        if (Config.Toggles.toggleCustomDiveForce) {
            data.field("diveForce").value = Config.CustomValues.diveForce;
            data.field("airDiveForce").value = Config.CustomValues.diveForce / Config.DefaultValues.diveMultiplier;
        } else {
            data.field("diveForce").value = Config.DefaultValues.diveForce;
            data.field("airDiveForce").value = Config.DefaultValues.airDiveForce;
        }
    }

    private changeJump(jumpMotor: Il2Cpp.Object): void {
        const targetJump = Config.Toggles.toggleCustomJumpForce ? Config.CustomValues.jumpForce : Config.DefaultValues.jumpForce;

        const jumpForce = jumpMotor.field<Il2Cpp.ValueType>("_jumpForce").value;
        jumpForce.field("y").value = targetJump;
    }

    public freezePlayer(state: boolean): void {
        try {
            const characterRigidBody = this.character!.method<Il2Cpp.Object>("get_RigidBody").invoke();
            characterRigidBody.method<void>("set_isKinematic").invoke(state);
        } catch (error: any) {
            Logger.warn(`[${this.name}::freezePlayer] No character Instance found: ${error.name}`);
            //Menu.toast()
        }
    }

    public static get Character(): Il2Cpp.Object | undefined {
        return this._character;
    }
}
