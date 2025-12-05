import { AssemblyHelper } from "../../core/AssemblyHelper";
import { BaseModule } from "../../core/BaseModule";
import { I18n } from "../../i18n/I18n";
import { Logger } from "../../logger/Logger";
import { UnityUtils } from "../../utils/UnityUtils";

/*
 * Every door has Levels::DoorDash::FakeDoorController component or Levels::CrownMaze::CrownMazeDoor (if lost temple map)
 * It has a boolean field IsFakeDoor or IsBreakable
 * If it returns false or true, we disable the GameObject using SetActive
 */

export class DoorManagerModule extends BaseModule {
    public readonly name = "DoorManager";

    // Classes
    private FakeDoorController!: Il2Cpp.Class;
    private CrownMazeDoor!: Il2Cpp.Class;

    public init(): void {
        this.FakeDoorController = AssemblyHelper.TheMultiplayerGuys.class("Levels.DoorDash.FakeDoorController");
        this.CrownMazeDoor = AssemblyHelper.TheMultiplayerGuys.class("Levels.CrownMaze.CrownMazeDoor");
    }

    public removeRealDoors(): void {
        if (this.processDoors(this.FakeDoorController, "get_IsFakeDoor", false)) {
            return;
        }
        if (this.processDoors(this.CrownMazeDoor, "get_IsBreakable", true)) {
            return;
        }

        Logger.toast(I18n.t("rounds_toasts.no_doors"));
    }

    private processDoors(doorClass: Il2Cpp.Class, methodName: string, methodShouldReturn: boolean): boolean {
        const doors = UnityUtils.FindObjectsOfTypeAll(doorClass);

        if (doors.length === 0) {
            Logger.debug(`[${this.name}::removeFakeDoors] No doors of ${doorClass.name}`);
            return false;
        }

        for (const door of doors) {
            const methodRetuned = door.method<boolean>(methodName).invoke();

            if (methodRetuned === methodShouldReturn) {
                const doorObject = UnityUtils.getGameObject(door);
                UnityUtils.SetActive(doorObject, false);
            }
        }
        return true;
    }
}
