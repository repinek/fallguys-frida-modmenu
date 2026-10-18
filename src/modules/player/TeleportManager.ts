import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { Logger } from "../../logger/Logger";
import { CharacterPhysicsModule } from "./CharacterPhysics";
import { UnityUtils } from "../../utils/UnityUtils";

export class TeleportManagerModule extends BaseModule {
    public readonly name = "TeleportManager";

    // Classes
    private ObjectiveReachEndZone!: Il2Cpp.Class;
    private GrabToQualify!: Il2Cpp.Class;
    private SpawnableCollectable!: Il2Cpp.Class;
    private ScoringBubble!: Il2Cpp.Class;
    private ScoredButton!: Il2Cpp.Class;

    public init(): void {
        this.ObjectiveReachEndZone = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone"); // finish
        this.GrabToQualify = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify"); // crown
        this.SpawnableCollectable = AssemblyHelper.TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"); // bubble unity levels
        this.ScoringBubble = AssemblyHelper.TheMultiplayerGuys.class("Levels.Progression.COMMON_ScoringBubble"); // bubble creative levels
        this.ScoredButton = AssemblyHelper.TheMultiplayerGuys.class("ScoredButton"); // trigger button unity
    }

    /**
     * Teleports the player to the target object's position.
     *
     * @param playerInstance The Player Object
     * @param targetInstance The destination Object
     * @param additionalY Vertical offset added to targetInstance position
     */
    private teleportTo(playerInstance: Il2Cpp.Object, targetInstance: Il2Cpp.Object, additionalY: number = 0): void {
        try {
            const targetPos = UnityUtils.getTransform(targetInstance).method<Il2Cpp.Object>("get_position").invoke(); // Vector3
            targetPos.field<number>("y").value += additionalY;

            // I was using transform for teleportation
            // We need to use rigid body instead
            const playerRigidbody = playerInstance.method<Il2Cpp.Object>("get_RigidBody").invoke();
            playerRigidbody.method<void>("set_position").invoke(targetPos);
        } catch (error: any) {
            Logger.warn(`[${this.name}::teleportTo] No character, ${error.name}`);
        }
    }

    private get character(): Il2Cpp.Object | undefined {
        return CharacterPhysicsModule.Character;
    }

    public teleportToFinish(): void {
        // TODO: fix, doesn't work
        // UPD: since character is cached, we probably can re-check it here
        // I don't see a reason to do that currently, since it's not crashing or anything
        if (!this.character) {
            Logger.debug(`[${this.name}::teleportToFinish] No character`);
            return;
        }

        const targetClasses = [this.ObjectiveReachEndZone, this.GrabToQualify];

        for (const targetClass of targetClasses) {
            const objects = UnityUtils.FindObjectsOfTypeAll(targetClass);

            if (objects.length > 0) {
                this.teleportTo(this.character, objects.get(0), 5);
                return;
            }

            Logger.debug(`[${this.name}::teleportToFinish] No object`);
            //Menu.toast(en.messages.no_finish, 0);
        }
    }

    public teleportToScore(): void {
        if (!this.character) {
            Logger.debug(`[${this.name}::teleportToScore] No character`);
            return;
        }

        try {
            let target = this.findUnityBubbles();

            if (!target) target = this.findCreativeBubbles();

            if (!target) target = this.findScoredButton();

            if (target) {
                this.teleportTo(this.character, target, 1);
            } else {
                Logger.debug(`[${this.name}::teleportToScore] No object`);
            }
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    private findUnityBubbles(): Il2Cpp.Object | undefined {
        const unityBubbles = UnityUtils.FindObjectsOfTypeAll(this.SpawnableCollectable);
        for (const bubble of unityBubbles) {
            if (bubble.method<boolean>("get_Spawned").invoke()) {
                return bubble;
            }
        }
        return undefined;
    }

    private findCreativeBubbles(): Il2Cpp.Object | undefined {
        const creativeBubbles = UnityUtils.FindObjectsOfTypeAll(this.ScoringBubble);
        for (const bubble of creativeBubbles) {
            // if award is negative points: skip
            if (bubble.field<number>("_pointsAwarded").value <= 0) continue;

            const bubbleHandle = bubble.field<Il2Cpp.Object>("_bubbleHandle").value; // LevelEditorBubbleHandler class
            if (bubbleHandle.field<boolean>("_spawned").value) {
                return bubble;
            }
        }
    }

    private findScoredButton(): Il2Cpp.Object | undefined {
        const scoredButtons = UnityUtils.FindObjectsOfTypeAll(this.ScoredButton);
        for (const button of scoredButtons) {
            if (button.field<boolean>("_isAnActiveTarget").value) return button;
        }
    }
}
