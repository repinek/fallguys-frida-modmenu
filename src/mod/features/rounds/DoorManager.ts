import { AssemblyHelper } from "../../../engine/AssemblyHelper";
import { Component } from "../../../engine/wrappers/Component";
import { GameObject } from "../../../engine/wrappers/GameObject";
import { Resources } from "../../../engine/wrappers/Resources";
import { Logger } from "../../../utils/Logger";
import { I18n } from "../../i18n/I18n";

/*
 * Every door has Levels::DoorDash::FakeDoorController component or Levels::CrownMaze::CrownMazeDoor (if lost temple map)
 * It has a boolean field IsFakeDoor or IsBreakable
 * If it returns false or true, we disable the GameObject using SetActive
 */

export class DoorManager {
    // Classes
    private static FakeDoorController: Il2Cpp.Class;
    private static CrownMazeDoor: Il2Cpp.Class;

    static init(): void {
        this.FakeDoorController = AssemblyHelper.TheMultiplayerGuys.class("Levels.DoorDash.FakeDoorController");
        this.CrownMazeDoor = AssemblyHelper.TheMultiplayerGuys.class("Levels.CrownMaze.CrownMazeDoor");

        Logger.info("[DoorManager::init] Initialized");
    }

    static removeRealDoors(): void {
        if (this.processDoors(this.FakeDoorController, "get_IsFakeDoor", false)) {
            return;
        }
        if (this.processDoors(this.CrownMazeDoor, "get_IsBreakable", true)) {
            return;
        }

        Logger.toast(I18n.t("rounds_toasts.no_doors"));
    }

    private static processDoors(doorClass: Il2Cpp.Class, methodName: string, methodShouldReturn: boolean): boolean {
        const doors = Resources.findObjectsOfTypeAll(doorClass.type.object);

        if (doors.length === 0) {
            Logger.debug(`[${this.name}::removeFakeDoors] No doors of ${doorClass.name}`);
            return false;
        }

        for (const door of doors) {
            const methodRetuned = door.method<boolean>(methodName).invoke();

            if (methodRetuned === methodShouldReturn) {
                const doorObject = Component.getGameObject(door);
                GameObject.setActive(doorObject, false);
            }
        }
        return true;
    }
}
