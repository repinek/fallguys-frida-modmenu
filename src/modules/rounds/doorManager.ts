import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { Logger } from "../../logger/logger.js";
import { UnityUtils } from "../../utils/unityUtils.js";

export class DoorManagerModule extends BaseModule {
    public name = "DoorManager";

    private FakeDoorController!: Il2Cpp.Class;
    private CrownMazeDoor!: Il2Cpp.Class;

    public init(): void {
        this.FakeDoorController = AssemblyHelper.TheMultiplayerGuys.class("Levels.DoorDash.FakeDoorController");
        this.CrownMazeDoor = AssemblyHelper.TheMultiplayerGuys.class("Levels.CrownMaze.CrownMazeDoor");
    }

    public removeRealDoors(): void {
        this.processDoors(this.FakeDoorController, "get_IsFakeDoor", false);
        this.processDoors(this.CrownMazeDoor, "get_IsBreakable", true);
    }

    private processDoors(doorClass: Il2Cpp.Class, methodName: string, methodShouldReturn: boolean): void {
        const doors = UnityUtils.findObjectsOfTypeAll(doorClass);

        if (doors.length === 0) {
            Logger.debug(`[${this.name}::removeFakeDoors] No doors of ${doorClass.name}`);
            return;
        }

        for (const door of doors) {
            const methodRetuned = door.method<boolean>(methodName).invoke();

            if (methodRetuned === methodShouldReturn) {
                const doorObject = UnityUtils.getGameObject(door);
                UnityUtils.setActive(doorObject, false);
            }
        }
    }
}
