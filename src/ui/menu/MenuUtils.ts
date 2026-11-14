import { BuildInfo } from "../../modules/BuildInfo";
import { MatchInfo } from "../../modules/MatchInfo";
import { UwUify } from "../../modules/UwUify";

import { CharacterPhysics } from "../../modules/player/CharacterPhysics";
import { TeleportManager } from "../../modules/player/TeleportManager";

import { DoorManager } from "../../modules/rounds/DoorManager";
import { TipToeManager } from "../../modules/rounds/TipToeManager";

import { FGDebug } from "../../modules/FGDebug";
import { GraphicsManager } from "../../modules/GraphicsManager";
import { UICanvas } from "../../modules/UICanvas";

import { MenuBuilder } from "./MenuBuilder";

import { UnityUtils } from "../../utils/UnityUtils";
import { add, CENTER } from "frida-java-menu";

export class MenuUtils {
    public static modules: {
        buildInfo?: typeof BuildInfo;
        matchInfo?: typeof MatchInfo;
        uwuify?: typeof UwUify;
        characterPhysics?: typeof CharacterPhysics;
        teleportManager?: typeof TeleportManager;
        doorManager?: typeof DoorManager;
        tipToeManager?: typeof TipToeManager;
        fgDebug?: typeof FGDebug;
        graphicsManager?: typeof GraphicsManager;
        uiCanvas?: typeof UICanvas;
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
        m.buildInfo = BuildInfo;
        m.matchInfo = MatchInfo;
        m.uwuify = UwUify;

        // Player
        m.characterPhysics = CharacterPhysics;
        m.teleportManager = TeleportManager;

        // Rounds
        m.doorManager = DoorManager;
        m.tipToeManager = TipToeManager;

        // Visuals
        m.fgDebug = FGDebug;
        m.graphicsManager = GraphicsManager;
        m.uiCanvas = UICanvas;
    }

    /** Adds center text in menu */
    static addCenterText(text: string): void {
        if (MenuBuilder.layout) {
            const textToAdd = MenuBuilder.layout.textView(text);
            textToAdd.gravity = CENTER;
            add(textToAdd);
        }
    }
}
