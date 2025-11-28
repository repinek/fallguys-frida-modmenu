import { ModuleManager } from "../core/moduleManager.js";

import { Config } from "../data/config.js";
import { ObsidianConfig } from "../data/layoutConfig.js";
import { ModPreferences } from "../data/modPreferences.js";

import { I18n } from "../i18n/i18n.js";

import { Logger } from "../logger/logger.js";

import { BuildInfoModule } from "../modules/game/buildInfo.js";
import { MatchInfoModule } from "../modules/game/matchInfo.js";

import { CharacterPhysicsModule } from "../modules/player/characterPhysics.js";
import { TeleportManagerModule } from "../modules/player/teleportManager.js";

import { DoorManagerModule } from "../modules/rounds/doorManager.js";
import { TipToeModule } from "../modules/rounds/tipToeManager.js";

import { FGDebugModule } from "../modules/visuals/fgDebug.js";
import { GraphicsManagerModule } from "../modules/visuals/graphicsManager.js";
import { ModalType_enum, OkButtonType_enum, PopupManagerModule } from "../modules/visuals/popupManager.js";
import { UICanvasModule } from "../modules/visuals/uiCanvas.js";

import * as javaUtils from "../utils/javaUtils.js";
import { UnityUtils } from "../utils/unityUtils.js";

export class MenuBuilder {
    private static buildInfo?: BuildInfoModule;
    private static matchInfo?: MatchInfoModule;

    private static characterPhysics?: CharacterPhysicsModule;
    private static teleportManager?: TeleportManagerModule;

    private static doorManager?: DoorManagerModule;
    private static tipToe?: TipToeModule;

    private static fgDebug?: FGDebugModule;
    private static graphics?: GraphicsManagerModule;
    private static popupManager?: PopupManagerModule;
    private static uiCanvas?: UICanvasModule;

    public static init() {
        if (Java.available)
            Menu.waitForInit(MenuBuilder.build);
    }

    private static build() {
        try {
            const layout = new Menu.ObsidianLayout(ObsidianConfig);

            const title = I18n.t("menu.info.title");
            const desc = `v${ModPreferences.VERSION} (${ModPreferences.ENV})`;

            const composer = new Menu.Composer(title, desc, layout);
            composer.icon(Config.MOD_MENU_ICON_URL, "Web");

            MenuBuilder.initContent(layout);

            composer.show();
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    private static getModules() {
        // Game
        this.buildInfo = ModuleManager.get(BuildInfoModule);
        this.matchInfo = ModuleManager.get(MatchInfoModule);

        // Player
        this.characterPhysics = ModuleManager.get(CharacterPhysicsModule);
        this.teleportManager = ModuleManager.get(TeleportManagerModule);

        // Rounds
        this.doorManager = ModuleManager.get(DoorManagerModule);
        this.tipToe = ModuleManager.get(TipToeModule);

        // Visuals
        this.fgDebug = ModuleManager.get(FGDebugModule);
        this.graphics = ModuleManager.get(GraphicsManagerModule);
        this.popupManager = ModuleManager.get(PopupManagerModule);
        this.uiCanvas = ModuleManager.get(UICanvasModule);
    }

    private static initContent(layout: Menu.ObsidianLayout) {
        MenuBuilder.getModules();

        if (ModPreferences.ENV === "dev" || ModPreferences.ENV === "staging") {
            MenuBuilder.initDebugContent(layout);
        }

        const movement = layout.textView(I18n.t("menu.tabs.movement"));
        movement.gravity = Menu.Api.CENTER;
        Menu.add(movement);

        const round = layout.textView(I18n.t("menu.tabs.round"));
        round.gravity = Menu.Api.CENTER;
        Menu.add(round);

        const teleports = layout.textView(I18n.t("menu.tabs.teleports"));
        teleports.gravity = Menu.Api.CENTER;
        Menu.add(teleports);

        const utility = layout.textView(I18n.t("menu.tabs.utility"));
        utility.gravity = Menu.Api.CENTER;
        Menu.add(utility);
    }

    private static initDebugContent(layout: Menu.ObsidianLayout) {
        const debugtab = layout.textView("Debug");
        debugtab.gravity = Menu.Api.CENTER;
        Menu.add(debugtab);

        Menu.add(
            layout.button(
                "System.exit",
                () => {
                    Menu.toast("Hold for exit", 0);
                },
                () => {
                    // Long Callback
                    javaUtils.exitFromApp();
                }
            )
        );

        Menu.add(
            layout.button("Debug", () => {
                UnityUtils.runInMain(() => {
                    this.popupManager?.showPopup("Test Popup", "Message of Test Popup", ModalType_enum.MT_OK, OkButtonType_enum.Green);
                });
            })
        );

        Menu.add(layout.textView(I18n.t("hi.hi")));
    }
}
