import { BaseModule } from "./baseModule.js";

import { AntiAFKModule } from "../modules/antiAFK.js";
import { BanBypassModule } from "../modules/banBypass.js";
import { BuildInfoModule } from "../modules/buildInfo.js";
import { CatapultModule } from "../modules/catapult.js";
import { CharacterPhysicsModule } from "../modules/characterPhysics.js";
import { FGDebugModule } from "../modules/fgDebug.js";
import { GraphicsManagerModule } from "../modules/graphicsManager.js";
import { NetworkModule } from "../modules/network.js";
import { PopupManagerModule } from "../modules/popupManager.js";
import { TipToeModule } from "../modules/tipToeManager.js";
import { UICanvasModule } from "../modules/uiCanvas.js";

import { Logger } from "../utils/logger.js";

export class ModuleManager {
    // prettier-ignore
    private static modules: BaseModule[] = [
        new AntiAFKModule(),
        new BanBypassModule(),
        new BuildInfoModule(),
        new CatapultModule(),
        new CharacterPhysicsModule(),
        new FGDebugModule(),
        new GraphicsManagerModule(),
        new NetworkModule(),
        new PopupManagerModule(),
        new TipToeModule(),
        new UICanvasModule(),
    ];

    /** Initializes all modules by calling init() in module */
    public static initAll() {
        Logger.info("[ModuleManager] Initializing modules...");

        this.modules.forEach(module => {
            try {
                module.init();
                module.onEnable();
                Logger.debug(`[ModuleManager] ${module.name} module loaded`);
            } catch (error: any) {
                Logger.errorThrow(error, `[ModuleManager] Failed to load ${module.name} module`);
            }
        });

        Logger.info("[ModuleManager] All modules Initialized");
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
