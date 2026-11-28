import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { GameDefaults } from "../../../fallguys/GameDefaults";
import { FallGuysCharacterController } from "../../../fallguys/wrappers/FallGuysCharacterController";
import { MotorFunctionJump } from "../../../fallguys/wrappers/FG.Common/Character/MotorFunctionJump";
import { CharacterControllerData } from "../../../fallguys/wrappers/FG.Common/CharacterControllerData";
import { GlobalGameStateClient } from "../../../fallguys/wrappers/FGClient/GlobalGameStateClient";
import { Logger } from "../../../utils/Logger";
import { ModSettings } from "../../data/ModSettings";

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
    static init(): void {
        const CharacterDataMonitor = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
        const MotorFunctionJump = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.Character.MotorFunctionJump");
        const MPGNetMotorTasks = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.MPGNetMotorTasks");

        // Methods
        //@ts-ignore
        CharacterDataMonitor.method<boolean>("CheckCharacterControllerData", 1).implementation = this.checkCharacterControllerDataHook;
        //@ts-ignore
        MotorFunctionJump.method<boolean>("CanJump").implementation = this.canJumpHook;
        //@ts-ignore
        MPGNetMotorTasks.method<void>("SendMessage", 1).implementation = this.sendMessageHook;

        Logger.info("[CharacterPhysics::init] Initialized");
    }

    private static checkCharacterControllerDataHook(rawCharacter: Il2Cpp.Object): boolean {
        const character = new FallGuysCharacterController(rawCharacter);

        const data = character.data;
        const jumpMotor = character.jumpMotorFunction;

        CharacterPhysics.changeSpeed(data);
        CharacterPhysics.changeGravity(data);
        CharacterPhysics.changeDive(data);
        CharacterPhysics.changeJump(jumpMotor);

        return true;
    }


    private static changeSpeed(data: CharacterControllerData): void {
        const speed = ModSettings.customSpeed ? ModSettings.normalMaxSpeed : GameDefaults.normalMaxSpeed;

        data.normalMaxSpeed = speed;
        data.carryMaxSpeed = speed;
        data.grabbingMaxSpeed = speed;
    }

    private static changeGravity(data: CharacterControllerData): void {
        let gravity: number = GameDefaults.maxGravityVelocity;

        // kinda messy, idk how better
        if (ModSettings.customGravity) {
            if (ModSettings.noGravity) {
                gravity = 0;
            } else if (ModSettings.negativeGravity) {
                gravity = -ModSettings.maxGravityVelocity;
            } else {
                gravity = ModSettings.maxGravityVelocity;
            }
        }

        data.maxGravityVelocity = gravity
    }

    private static changeDive(data: CharacterControllerData): void {
        const diveSensitivity = ModSettings.enable360Dives ? 69420 : GameDefaults.divePlayerSensitivity;
        data.divePlayerSensitivity = diveSensitivity

        if (ModSettings.customDiveForce) {
            data.diveForce = ModSettings.diveForce;
            data.airDiveForce = ModSettings.diveForce / GameDefaults.diveMultiplier;
        } else {
            data.diveForce = GameDefaults.diveForce
            data.airDiveForce = GameDefaults.airDiveForce;
        }
    }

    private static changeJump(jumpMotor: MotorFunctionJump): void {
        const targetJump = ModSettings.customJumpForce ? ModSettings.jumpForce : GameDefaults.jumpForce;
        jumpMotor.jumpForce.y = targetJump;
    }

    static freezePlayer(state: boolean): void {
        if (GlobalGameStateClient.instance?.gameStateView.isGamePlaying && this.localCharacter) {
            this.localCharacter.rigidBody.isKinematic = state;
        } else {
            // not in game say it
        }
    }

    static get localCharacter(): FallGuysCharacterController | undefined {
        return GlobalGameStateClient.instance?.playerManager.localCharacter;
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
}
