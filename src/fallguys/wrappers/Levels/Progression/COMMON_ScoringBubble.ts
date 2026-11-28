import { AssemblyHelper } from "../../../../engine/AssemblyHelper";
import { Component } from "../../../../engine/wrappers/Component";
import { LevelEditorBubbleHandler } from "../../LevelEditorBubbleHandler";

export class COMMON_ScoringBubble extends Component {
    protected static override _class: Il2Cpp.Class | null = null;

    static override get class(): Il2Cpp.Class {
        return (this._class ??= AssemblyHelper.TheMultiplayerGuys.class("Levels.Progression.COMMON_ScoringBubble"));
    }

    get pointsAwarded(): number {
        return this.field<number>("_pointsAwarded").value;
    }

    get bubbleHandle(): LevelEditorBubbleHandler {
        return new LevelEditorBubbleHandler(this.field<Il2Cpp.Object>("_bubbleHandle").value);
    }
}
