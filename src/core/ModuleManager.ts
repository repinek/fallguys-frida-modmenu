import { BaseModule } from "./BaseModule";

// Game
import { BanBypassModule } from "../modules/game/BanBypass";
import { BuildInfoModule } from "../modules/game/BuildInfo";
import { MatchInfoModule } from "../modules/game/MatchInfo";
import { UwUifyModule } from "../modules/game/UwUify";

// Network
import { CatapultModule } from "../modules/network/Catapult";
import { NetworkModule } from "../modules/network/Network";
import { TokenLoginModule } from "../modules/network/TokenLogin";

// Player
import { AntiAFKModule } from "../modules/player/AntiAFK";
import { CharacterPhysicsModule } from "../modules/player/CharacterPhysics";
import { TeleportManagerModule } from "../modules/player/TeleportManager";

// Rounds
import { DoorManagerModule } from "../modules/rounds/DoorManager";
import { TipToeManagerModule } from "../modules/rounds/TipToeManager";

// Visuals
import { FGDebugModule } from "../modules/visuals/FGDebug";
import { GraphicsManagerModule } from "../modules/visuals/GraphicsManager";
import { UICanvasModule } from "../modules/visuals/UICanvas";

import { Logger } from "../logger/Logger";

export class ModuleManager {
    public readonly name = "ModuleManager";

    // prettier-ignore
    private static modules: BaseModule[] = [
        // sorted the same as imports
        new BanBypassModule(),
        new BuildInfoModule(),
        new MatchInfoModule(),
        new UwUifyModule(),
        new CatapultModule(),
        new NetworkModule(),
        new TokenLoginModule(),
        new AntiAFKModule(),
        new CharacterPhysicsModule(),
        new TeleportManagerModule(),
        new DoorManagerModule(),
        new TipToeManagerModule(),
        new FGDebugModule(),
        new GraphicsManagerModule(),
        new UICanvasModule(),
    ];

    /** Initializes all modules by calling init() in module */
    static initAll() {
        Logger.info(`[${this.name}::initAll] Initializing modules...`);

        this.modules.forEach(module => {
            try {
                module.init();
                module.initHooks();
                Logger.debug(`[${this.name}::initAll] ${module.name} module loaded`);
            } catch (error: any) {
                Logger.errorThrow(error, `[${this.name}::InitAll] Failed to load ${module.name} module`);
            }
        });

        Logger.info(`[${this.name}::initAll] All modules Initialized`);
    }

    /**
     * Finds the active instance of a module
     *
     * @param moduleClass The class of the module
     */
    static get<T extends BaseModule>(moduleClass: new (...args: any[]) => T): T | undefined {
        return this.modules.find(module => module instanceof moduleClass) as T | undefined;
    }
}
