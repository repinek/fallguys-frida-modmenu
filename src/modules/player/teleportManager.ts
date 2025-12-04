import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { Logger } from "../../logger/logger.js";
import { CharacterPhysicsModule } from "./characterPhysics.js";
import { UnityUtils } from "../../utils/unityUtils.js";

// TODO: describe issue here

export class TeleportManagerModule extends BaseModule {
    public readonly name = "TeleportManager";

    private readonly TELEPORT_COOLDOWN = 500;

    // Classes
    private ObjectiveReachEndZone!: Il2Cpp.Class;
    private GrabToQualify!: Il2Cpp.Class;
    private SpawnableCollectable!: Il2Cpp.Class;
    private ScoringBubble!: Il2Cpp.Class;
    private ScoredButton!: Il2Cpp.Class;

    private lastTeleportTime = 0;

    public init(): void {
        this.ObjectiveReachEndZone = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone"); // finish
        this.GrabToQualify = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify"); // crown
        this.SpawnableCollectable = AssemblyHelper.TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"); // bubble unity levels
        this.ScoringBubble = AssemblyHelper.TheMultiplayerGuys.class("Levels.Progression.COMMON_ScoringBubble"); // bubble creative levels
        this.ScoredButton = AssemblyHelper.TheMultiplayerGuys.class("ScoredButton"); // trigger button unity
    }

    /**
     * Behavior:
     * - if false: Shows toast with time you need to wait
     *
     * @returns `true` if allowed, `false` if on cooldown
     */
    private checkCooldown(): boolean {
        const currentTime = Date.now();
        const diff = currentTime - this.lastTeleportTime;

        if (diff < this.TELEPORT_COOLDOWN) {
            const remaining = ((this.TELEPORT_COOLDOWN - diff) / 1000).toFixed(1);
            Menu.toast(`Wait ${remaining}s`, 0);
            return false;
        }

        this.lastTeleportTime = currentTime;
        return true;
    }

    /**
     * Teleports the player to the target object's position.
     *
     * @param playerInstance The Player Object
     * @param targetInstance The destination Object
     */
    private teleportTo(playerInstance: Il2Cpp.Object, targetInstance: Il2Cpp.Object): void {
        try {
            // prettier-ignore
            const targetTransform = UnityUtils.getTransform(targetInstance);
            const targetPos = targetTransform.method<Il2Cpp.Object>("get_position").invoke();

            // prettier-ignore
            const playerTransform = UnityUtils.getTransform(playerInstance);
            playerTransform.method<Il2Cpp.Object>("set_position").invoke(targetPos);
        } catch (error: any) {
            Logger.warn(`[${this.name}::teleportTo] No character, ${error.name}`);
        }
    }

    private get character(): Il2Cpp.Object | undefined {
        return CharacterPhysicsModule.Character;
    }

    public teleportToFinish(): void {
        if (!this.checkCooldown()) return;

        // TODO: fix, doesn't work
        if (!this.character) {
            Logger.debug(`[${this.name}::teleportToFinish] No character`);
            return;
        }

        const targetClasses = [this.ObjectiveReachEndZone, this.GrabToQualify];

        for (const targetClass of targetClasses) {
            const objects = UnityUtils.FindObjectsOfTypeAll(targetClass);

            if (objects.length > 0) {
                this.teleportTo(this.character, objects.get(0));
                return;
            }

            Logger.debug(`[${this.name}::teleportToFinish] No object`);
            //Menu.toast(en.messages.no_finish, 0);
        }
    }

    public teleportToScore(): void {
        if (!this.checkCooldown()) return;

        if (!this.character) {
            Logger.debug(`[${this.name}::teleportToScore] No character`);
            return;
        }

        try {
            let target = this.findUnityBubbles();

            if (!target) target = this.findCreativeBubbles();

            if (!target) target = this.findScoredButton();

            if (target) {
                this.teleportTo(this.character, target);
            } else {
                Logger.debug(`[${this.name}::teleportToScore] No object`);
                //menu.toast
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

            const bubbleHandle = bubble.field<Il2Cpp.Object>("_bubbleHandle").value;
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
