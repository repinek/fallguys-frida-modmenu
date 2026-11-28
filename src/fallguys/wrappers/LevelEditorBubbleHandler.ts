// extends LevelEditorActiveObjectBase in original
export class LevelEditorBubbleHandler extends Il2Cpp.Object {
    get spawned(): boolean {
        return this.field<boolean>("_spawned").value;
    }
}
