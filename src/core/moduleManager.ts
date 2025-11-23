import { BaseModule } from "./baseModule.js";

import { Logger } from "../utils/logger.js";

import { GraphicsModule } from "../modules/graphics.js";

export class ModuleManager {
    // prettier-ignore
    private static modules: BaseModule[] = [
        new GraphicsModule()
    ];

    /**
     * Initializes all modules by calling init() in module
     */
    public static initAll() {
        Logger.info("[ModuleManager] Initializing modules...");

        this.modules.forEach(module => {
            try {
                module.init();
                Logger.debug(`[ModuleManager] ${module.name} loaded`);
            } catch (error: any) {
                Logger.errorThrow(error, `[ModuleManager] Failed to load ${module.name}`);
            }
        });
    }
    
    /**
     * Finds the active instance of a module
     * 
     * @param moduleClass The class of the module to find
     */
    public static get<T extends BaseModule>(moduleClass: new (...args: any[]) => T): T | undefined {
        return this.modules.find(module => module instanceof moduleClass) as T | undefined;
    }
}
