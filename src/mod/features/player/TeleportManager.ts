import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { Component } from "../../../engine/wrappers/Component";
import { Resources } from "../../../engine/wrappers/Resources";
import { Logger } from "../../../utils/Logger";
import { CharacterPhysics } from "./CharacterPhysics";

export class TeleportManager {
    // Classes
    private static ObjectiveReachEndZone: Il2Cpp.Class;
    private static GrabToQualify: Il2Cpp.Class;
    private static SpawnableCollectable: Il2Cpp.Class;
    private static ScoringBubble: Il2Cpp.Class;
    private static ScoredButton: Il2Cpp.Class;

    static init(): void {
        this.ObjectiveReachEndZone = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone"); // finish
        this.GrabToQualify = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify"); // crown
        this.SpawnableCollectable = AssemblyHelper.TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"); // bubble unity levels
        this.ScoringBubble = AssemblyHelper.TheMultiplayerGuys.class("Levels.Progression.COMMON_ScoringBubble"); // bubble creative levels
        this.ScoredButton = AssemblyHelper.TheMultiplayerGuys.class("ScoredButton"); // trigger button unity

        Logger.info("[TeleportManager::init] Initialized");
    }

    /**
     * Teleports the player to the target object's position.
     *
     * @param playerInstance The Player Object
     * @param targetInstance The destination Object
     * @param additionalY Vertical offset added to targetInstance position
     */
    private static teleportTo(playerInstance: Il2Cpp.Object, targetInstance: Il2Cpp.Object, additionalY: number = 0): void {
        try {
            const targetPos = Component.getTransform(targetInstance).method<Il2Cpp.Object>("get_position").invoke(); // Vector3
            targetPos.field<number>("y").value += additionalY;

            // I was using transform for teleportation
            // We need to use rigid body instead
            const playerRigidbody = playerInstance.method<Il2Cpp.Object>("get_RigidBody").invoke();
            playerRigidbody.method<void>("set_position").invoke(targetPos);
        } catch (error) {
            Logger.warn(`[${this.name}::teleportTo] No character, ${error}`);
        }
    }

    private static get character(): Il2Cpp.Object | undefined {
        return CharacterPhysics.Character;
    }

    static teleportToFinish(): void {
        // TODO: fix, doesn't work
        // UPD: since character is cached, we probably can re-check it here
        // I don't see a reason to do that currently, since it's not crashing or anything
        if (!this.character) {
            Logger.debug(`[${this.name}::teleportToFinish] No character`);
            return;
        }

        const targetClasses = [this.ObjectiveReachEndZone, this.GrabToQualify];

        for (const targetClass of targetClasses) {
            const objects = Resources.findObjectsOfTypeAll(targetClass.type.object);

            if (objects.length > 0) {
                this.teleportTo(this.character, objects.get(0), 5);
                return;
            }

            Logger.debug(`[${this.name}::teleportToFinish] No object`);
            //Menu.toast(en.messages.no_finish, 0);
        }
    }

    static teleportToScore(): void {
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
        } catch (error) {
            Logger.errorThrow(error);
        }
    }

    private static findUnityBubbles(): Il2Cpp.Object | undefined {
        const unityBubbles = Resources.findObjectsOfTypeAll(this.SpawnableCollectable.type.object);
        for (const bubble of unityBubbles) {
            if (bubble.method<boolean>("get_Spawned").invoke()) {
                return bubble;
            }
        }
        return undefined;
    }

    private static findCreativeBubbles(): Il2Cpp.Object | undefined {
        const creativeBubbles = Resources.findObjectsOfTypeAll(this.ScoringBubble.type.object);
        for (const bubble of creativeBubbles) {
            // if award is negative points: skip
            if (bubble.field<number>("_pointsAwarded").value <= 0) continue;

            const bubbleHandle = bubble.field<Il2Cpp.Object>("_bubbleHandle").value; // LevelEditorBubbleHandler class
            if (bubbleHandle.field<boolean>("_spawned").value) {
                return bubble;
            }
        }
    }

    private static findScoredButton(): Il2Cpp.Object | undefined {
        const scoredButtons = Resources.findObjectsOfTypeAll(this.ScoredButton.type.object);
        for (const button of scoredButtons) {
            if (button.field<boolean>("_isAnActiveTarget").value) return button;
        }
    }
}
