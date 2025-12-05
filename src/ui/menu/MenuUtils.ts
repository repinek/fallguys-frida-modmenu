import { ModuleManager } from "../../core/moduleManager.js";

import { BuildInfoModule } from "../../modules/game/buildInfo.js";
import { MatchInfoModule } from "../../modules/game/matchInfo.js";
import { UwUifyModule } from "../../modules/game/uwuify.js";

import { CharacterPhysicsModule } from "../../modules/player/characterPhysics.js";
import { TeleportManagerModule } from "../../modules/player/teleportManager.js";

import { DoorManagerModule } from "../../modules/rounds/doorManager.js";
import { TipToeManagerModule } from "../../modules/rounds/tipToeManager.js";

import { FGDebugModule } from "../../modules/visuals/fgDebug.js";
import { GraphicsManagerModule } from "../../modules/visuals/graphicsManager.js";
import { UICanvasModule } from "../../modules/visuals/uiCanvas.js";

import { MenuBuilder } from "./MenuBuilder.js";

import { UnityUtils } from "../../utils/unityUtils.js";

export class MenuUtils {
    public static modules: {
        buildInfo?: BuildInfoModule;
        matchInfo?: MatchInfoModule;
        uwuify?: UwUifyModule;
        characterPhysics?: CharacterPhysicsModule;
        teleportManager?: TeleportManagerModule;
        doorManager?: DoorManagerModule;
        tipToeManager?: TipToeManagerModule;
        fgDebug?: FGDebugModule;
        graphicsManager?: GraphicsManagerModule;
        uiCanvas?: UICanvasModule;
    } = {};

    /** Creates a callback wrapper over UnityUtils.runInMain */
    static run<T extends any[]>(action: (...args: T) => void): (...args: T) => void {
        return (...args: T) => {
            UnityUtils.runInMain(() => action(...args));
        };
    }

    public static getModules(): void {
        const m = this.modules;

        // Game
        m.buildInfo = ModuleManager.get(BuildInfoModule);
        m.matchInfo = ModuleManager.get(MatchInfoModule);
        m.uwuify = ModuleManager.get(UwUifyModule);

        // Player
        m.characterPhysics = ModuleManager.get(CharacterPhysicsModule);
        m.teleportManager = ModuleManager.get(TeleportManagerModule);

        // Rounds
        m.doorManager = ModuleManager.get(DoorManagerModule);
        m.tipToeManager = ModuleManager.get(TipToeManagerModule);

        // Visuals
        m.fgDebug = ModuleManager.get(FGDebugModule);
        m.graphicsManager = ModuleManager.get(GraphicsManagerModule);
        m.uiCanvas = ModuleManager.get(UICanvasModule);
    }

    /** Adds center text in menu */
    static addCenterText(text: string): void {
        if (MenuBuilder.layout) {
            const textToAdd = MenuBuilder.layout.textView(text);
            textToAdd.gravity = Menu.Api.CENTER;
            Menu.add(textToAdd);
        }
    }
}
