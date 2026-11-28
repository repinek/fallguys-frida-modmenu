import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { Component } from "../../../engine/wrappers/Component";
import { Resources } from "../../../engine/wrappers/Resources";
import { FallGuysCharacterController } from "../../../fallguys/wrappers/FallGuysCharacterController";
import { COMMON_ScoringBubble } from "../../../fallguys/wrappers/Levels/Progression/COMMON_ScoringBubble";
import { SpawnableCollectable } from "../../../fallguys/wrappers/Levels/ScoreZone/SpawnableCollectable";
import { ScoredButton } from "../../../fallguys/wrappers/ScoredButton";
import { Logger } from "../../../utils/Logger";
import { InGameUtils } from "../../utils/InGameUtils";

export class TeleportManager {
    private static ObjectiveReachEndZone: Il2Cpp.Class; // finish
    private static GrabToQualify: Il2Cpp.Class; // crown

    static init(): void {
        this.ObjectiveReachEndZone = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone");
        this.GrabToQualify = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify");

        Logger.info("[TeleportManager::init] Initialized");
    }

    /** Teleports the player to the target object's position. */
    private static teleportTo(playerInstance: FallGuysCharacterController, targetInstance: Component, additionalY: number = 0): void {
        const targetPos = targetInstance.transform.position;
        targetPos.y += additionalY;

        playerInstance.rigidBody.position = targetPos;
    }

    static teleportToFinish(): void {
        if (!InGameUtils.isPlayingAndCharacterExist()) {
            // todo no character
            return;
        }

        const targetClasses = [this.ObjectiveReachEndZone, this.GrabToQualify];

        for (const targetClass of targetClasses) {
            const objects = Resources.findObjectsOfTypeAll(targetClass.type.object);

            if (objects.length > 0) {
                this.teleportTo(InGameUtils.localCharacter!, new Component(objects.get(0)), 5);
                return;
            }

            Logger.debug(`[TeleportManager::teleportToFinish] No object`);
            //Menu.toast(en.messages.no_finish, 0);
        }
    }

    static teleportToScore(): void {
        if (!InGameUtils.isPlayingAndCharacterExist()) {
            // todo no character
            return;
        }

        const target = this.findUnityBubble() ?? this.findCreativeBubble() ?? this.findScoredButton();

        if (target) {
            this.teleportTo(InGameUtils.localCharacter!, target, 1);
        } else {
            Logger.debug(`[TeleportManager::teleportToScore] No object`);
        }
    }

    private static findUnityBubble(): SpawnableCollectable | undefined {
        const unityBubbles = Resources.findObjectsOfTypeAll(SpawnableCollectable.class.type.object);

        for (const rawBubble of unityBubbles) {
            const bubble = new SpawnableCollectable(rawBubble);
            if (bubble.spawned) {
                return bubble;
            }
        }
    }

    private static findCreativeBubble(): COMMON_ScoringBubble | undefined {
        const creativeBubbles = Resources.findObjectsOfTypeAll(COMMON_ScoringBubble.class.type.object);

        for (const rawBubble of creativeBubbles) {
            const bubble = new COMMON_ScoringBubble(rawBubble);
            if (bubble.pointsAwarded <= 0) continue;

            if (bubble.bubbleHandle.spawned) {
                return bubble;
            }
        }
    }

    private static findScoredButton(): ScoredButton | undefined {
        const scoredButtons = Resources.findObjectsOfTypeAll(ScoredButton.class.type.object);

        for (const rawButton of scoredButtons) {
            const button = new ScoredButton(rawButton);
            if (button.isAnActiveTarget) return button;
        }
    }
}
