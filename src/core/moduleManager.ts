import { BaseModule } from "./baseModule.js";

// Game
import { BanBypassModule } from "../modules/game/banBypass.js";
import { BuildInfoModule } from "../modules/game/buildInfo.js";

// Network
import { CatapultModule } from "../modules/network/catapult.js";
import { NetworkModule } from "../modules/network/network.js";

// Player
import { AntiAFKModule } from "../modules/player/antiAFK.js";
import { CharacterPhysicsModule } from "../modules/player/characterPhysics.js";
import { TeleportManagerModule } from "../modules/player/teleportManager.js";

// Rounds
import { DoorManagerModule } from "../modules/rounds/doorManager.js";
import { TipToeModule } from "../modules/rounds/tipToeManager.js";

// Visuals
import { FGDebugModule } from "../modules/visuals/fgDebug.js";
import { GraphicsManagerModule } from "../modules/visuals/graphicsManager.js";
import { PopupManagerModule } from "../modules/visuals/popupManager.js";
import { UICanvasModule } from "../modules/visuals/uiCanvas.js";

import { Logger } from "../logger/logger.js";

export class ModuleManager {
    public name = "ModuleManager";

    // prettier-ignore
    private static modules: BaseModule[] = [
        new AntiAFKModule(),
        new BanBypassModule(),
        new BuildInfoModule(),
        new CatapultModule(),
        new CharacterPhysicsModule(),
        new DoorManagerModule(),
        new FGDebugModule(),
        new GraphicsManagerModule(),
        new NetworkModule(),
        new PopupManagerModule(),
        new TeleportManagerModule(),
        new TipToeModule(),
        new UICanvasModule(),
    ];

    /** Initializes all modules by calling init() in module */
    public static initAll() {
        Logger.info(`[${this.name}::InitAll] Initializing modules...`);

        this.modules.forEach(module => {
            try {
                module.init();
                module.onEnable();
                Logger.debug(`[${this.name}::InitAll] ${module.name} module loaded`);
            } catch (error: any) {
                Logger.errorThrow(error, `[${this.name}::InitAll] Failed to load ${module.name} module`);
            }
        });

        Logger.info(`[${this.name}::InitAll] All modules Initialized`);
    }

    /**
     * Finds the active instance of a module
     *
     * @param moduleClass The class of the module
     */
    public static get<T extends BaseModule>(moduleClass: new (...args: any[]) => T): T | undefined {
        return this.modules.find(module => module instanceof moduleClass) as T | undefined;
    }
}
