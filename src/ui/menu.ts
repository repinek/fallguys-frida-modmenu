import { ModuleManager } from "../core/moduleManager.js";

import { Config } from "../data/config.js";
import { ObsidianConfig } from "../data/layoutConfig.js";
import { ModPreferences } from "../data/modPreferences.js";

import { I18n } from "../i18n/i18n.js";

// import { InGameLogger } from "../logger/inGameLogger.js";
import { Logger } from "../logger/logger.js";

import { BuildInfoModule } from "../modules/game/buildInfo.js";
import { MatchInfoModule } from "../modules/game/matchInfo.js";

import { CharacterPhysicsModule } from "../modules/player/characterPhysics.js";
import { TeleportManagerModule } from "../modules/player/teleportManager.js";

import { DoorManagerModule } from "../modules/rounds/doorManager.js";
import { TipToeManagerModule } from "../modules/rounds/tipToeManager.js";

import { FGDebugModule } from "../modules/visuals/fgDebug.js";
import { GraphicsManagerModule } from "../modules/visuals/graphicsManager.js";
import { ModalType_enum, OkButtonType_enum, PopupManagerModule } from "../modules/visuals/popupManager.js";
import { UICanvasModule } from "../modules/visuals/uiCanvas.js";

import * as javaUtils from "../utils/javaUtils.js";
import { UnityUtils } from "../utils/unityUtils.js";

export class MenuBuilder {
    private static modules: {
        buildInfo?: BuildInfoModule;
        matchInfo?: MatchInfoModule;
        characterPhysics?: CharacterPhysicsModule;
        teleportManager?: TeleportManagerModule;
        doorManager?: DoorManagerModule;
        tipToeManager?: TipToeManagerModule;
        fgDebug?: FGDebugModule;
        graphicsManager?: GraphicsManagerModule;
        popupManager?: PopupManagerModule;
        uiCanvas?: UICanvasModule;
    } = {};

    public static init(): void {
        if (Java.available) {
            Menu.waitForInit(MenuBuilder.build);
        }
    }

    private static build(): void {
        try {
            const layout = new Menu.ObsidianLayout(ObsidianConfig);

            const title = I18n.t("menu.info.title");
            const desc = `v${ModPreferences.VERSION} (${ModPreferences.ENV})`;

            const composer = new Menu.Composer(title, desc, layout);
            composer.icon(Config.MOD_MENU_ICON_URL, "Web");

            MenuBuilder.buildContent(layout);

            composer.show();
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    private static getModules(): void {
        // Game
        this.modules.buildInfo = ModuleManager.get(BuildInfoModule);
        this.modules.matchInfo = ModuleManager.get(MatchInfoModule);

        // Player
        this.modules.characterPhysics = ModuleManager.get(CharacterPhysicsModule);
        this.modules.teleportManager = ModuleManager.get(TeleportManagerModule);

        // Rounds
        this.modules.doorManager = ModuleManager.get(DoorManagerModule);
        this.modules.tipToeManager = ModuleManager.get(TipToeManagerModule);

        // Visuals
        this.modules.fgDebug = ModuleManager.get(FGDebugModule);
        this.modules.graphicsManager = ModuleManager.get(GraphicsManagerModule);
        this.modules.popupManager = ModuleManager.get(PopupManagerModule);
        this.modules.uiCanvas = ModuleManager.get(UICanvasModule);
    }

    /** Creates a callback wrapper over UnityUtils.runInMain */
    private static run<T extends any[]>(action: (...args: T) => void): (...args: T) => void {
        return (...args: T) => {
            UnityUtils.runInMain(() => action(...args));
        };
    }

    private static buildContent(layout: Menu.ObsidianLayout): void {
        MenuBuilder.getModules();

        if (ModPreferences.ENV === "dev" || ModPreferences.ENV === "staging") {
            MenuBuilder.buildDebugTab(layout);
        }
        MenuBuilder.buildMovementTab(layout);
        MenuBuilder.buildRoundTab(layout);
        MenuBuilder.buildTeleportsTab(layout);
        MenuBuilder.buildUtilityTab(layout);
        MenuBuilder.buildOtherTab(layout);
    }

    private static buildDebugTab(layout: Menu.ObsidianLayout): void {
        const m = MenuBuilder.modules;
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
            layout.button("Create Test Popup", () => {
                UnityUtils.runInMain(() => {
                    m.popupManager?.showPopup("Test Popup", "Message of Test Popup", ModalType_enum.MT_OK, OkButtonType_enum.Green);
                });
            })
        );

        // yes i definitely need to other branch it but... sorry
        // Menu.add(
        //     layout.button(
        //         "Create Logger", 
        //         this.run(() => InGameLogger.createLogger())
        //     )
        // );

        Menu.add(layout.textView(I18n.t("hi.hi")));
    }

    private static buildMovementTab(layout: Menu.ObsidianLayout): void {
        const m = MenuBuilder.modules;
        const movement = layout.textView(I18n.t("menu.tabs.movement"));
        movement.gravity = Menu.Api.CENTER;
        Menu.add(movement);

        Menu.add(
            layout.toggle(I18n.t("menu.functions.360_dives"), (state: boolean) => {
                Config.Toggles.toggle360Dives = state;
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.air_jump"), (state: boolean) => {
                Config.Toggles.toggleAirJump = state;
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.freeze_player"), (state: boolean) => {
                m.characterPhysics?.freezePlayer(state);
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.fallguy_state"), (state: boolean) => {
                Config.Toggles.toggleDontSendFallGuyState = state;
            })
        );

        Menu.add(layout.textView(I18n.t("menu.functions.fallguy_state_warn")));

        Menu.add(
            layout.toggle(I18n.t("menu.functions.custom_speed"), (state: boolean) => {
                Config.Toggles.toggleCustomSpeed = state;
            })
        );

        Menu.add(
            layout.seekbar(I18n.t("menu.functions.speed_val"), 100, 1, (value: number) => {
                Config.CustomValues.normalMaxSpeed = value;
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.custom_gravity"), (state: boolean) => {
                Config.Toggles.toggleCustomGravity = state;
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.negative_gravity"), (state: boolean) => {
                Config.Toggles.toggleNegativeGravity = state;
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.no_gravity"), (state: boolean) => {
                Config.Toggles.toggleNoGravity = state;
            })
        );

        Menu.add(
            layout.seekbar(I18n.t("menu.functions.gravity_val"), 100, 0, (value: number) => {
                Config.CustomValues.maxGravityVelocity = value;
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.custom_jump_force"), (state: boolean) => {
                Config.Toggles.toggleCustomJumpForce = state;
            })
        );

        Menu.add(
            layout.seekbar(I18n.t("menu.functions.jump_force_val"), 100, 0, (value: number) => {
                Config.CustomValues.jumpForce = value;
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.custom_dive_force"), (state: boolean) => {
                Config.Toggles.toggleCustomDiveForce = state;
            })
        );

        Menu.add(
            layout.seekbar(I18n.t("menu.functions.seekbar_dive_strength"), 100, 0, (value: number) => {
                Config.CustomValues.diveForce = value;
            })
        );
    }

    private static buildRoundTab(layout: Menu.ObsidianLayout): void {
        const m = MenuBuilder.modules;
        const round = layout.textView(I18n.t("menu.tabs.round"));
        round.gravity = Menu.Api.CENTER;
        Menu.add(round);

        Menu.add(
            layout.button(
                I18n.t("menu.functions.hide_doors"),
                this.run(() => m.doorManager?.removeRealDoors())
            )
        );

        Menu.add(
            layout.button(
                I18n.t("menu.functions.hide_tiptoe"),
                this.run(() => m.tipToeManager?.removeFakeTipToe())
            )
        );
    }

    private static buildTeleportsTab(layout: Menu.ObsidianLayout): void {
        const m = MenuBuilder.modules;
        const teleports = layout.textView(I18n.t("menu.tabs.teleports"));
        teleports.gravity = Menu.Api.CENTER;
        Menu.add(teleports);

        // prettier-ignore
        Menu.add(
            layout.button(
                I18n.t("menu.functions.tp_finish_or_crown"),
                () => m.teleportManager?.teleportToFinish()
            )
        );

        // prettier-ignore
        Menu.add(
            layout.button(
                I18n.t("menu.functions.tp_score"),
                () => m.teleportManager?.teleportToScore()
            )
        );
    }

    private static buildUtilityTab(layout: Menu.ObsidianLayout): void {
        const m = MenuBuilder.modules;
        const utility = layout.textView(I18n.t("menu.tabs.utility"));
        utility.gravity = Menu.Api.CENTER;
        Menu.add(utility);

        Menu.add(
            layout.button(I18n.t("menu.functions.view_names"), () => {
                m.graphicsManager?.toggleNames();
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.custom_fov"), (state: boolean) => {
                Config.Toggles.toggleCustomFov = state;
            })
        );

        Menu.add(
            layout.seekbar(I18n.t("menu.functions.custom_fov_val"), 180, 1, (value: number) => {
                if (Config.Toggles.toggleCustomFov) {
                    m.graphicsManager?.changeFOV(value);
                }
            })
        );

        // prettier-ignore
        Menu.add(
            layout.toggle(
                I18n.t("menu.functions.disable_ui"),
                this.run((state: boolean) => m.uiCanvas?.toggleUICanvas(!state))
            )
        );

        // prettier-ignore
        Menu.add(
            layout.toggle(
                I18n.t("menu.functions.fgdebug"),
                this.run((state: boolean) => m.fgDebug?.toggleFGDebug(state))
            )
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.disable_analytics"), (state: boolean) => {
                Config.Toggles.toggleDisableAnalytics = state;
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.queued_players"), (state: boolean) => {
                Config.Toggles.toggleShowQueuedPlayers = state;
            })
        );

        Menu.add(
            layout.seekbar(I18n.t("menu.functions.custom_resolution"), 100, 1, (value: number) => {
                Config.CustomValues.ResolutionScale = value / 100;
                m.graphicsManager?.changeResolutionScale();
            })
        );

        Menu.add(
            layout.button(I18n.t("menu.functions.game_details"), () => {
                m.matchInfo?.showGameDetails();
            })
        );

        Menu.add(
            layout.button(I18n.t("menu.functions.server_details"), () => {
                m.matchInfo?.showGameDetails();
            })
        );

        Menu.add(
            layout.toggle(I18n.t("menu.functions.uwuify"), (state: boolean) => {
                Config.Toggles.toggleUwUifyMode = state;
            })
        );
    }

    private static buildOtherTab(layout: Menu.ObsidianLayout): void {
        const m = MenuBuilder.modules;
        const other = layout.textView(I18n.t("menu.tabs.other"));
        other.gravity = Menu.Api.CENTER;
        Menu.add(other);

        Menu.add(layout.button(I18n.t("menu.other.github_url"), () => javaUtils.openURL(Config.GITHUB_URL)));
        Menu.add(layout.button(I18n.t("menu.other.discord_url"), () => javaUtils.openURL(Config.DISCORD_URL)));

        Menu.add(
            layout.button(
                I18n.t("menu.other.credits"),
                this.run(() => this.showCreditsPopup())
            )
        );

        const buildInfo = layout.textView(m.buildInfo!.getShortString());
        buildInfo.gravity = Menu.Api.CENTER;
        Menu.add(buildInfo);
    }

    private static showCreditsPopup(): void {
        const m = MenuBuilder.modules;
        const title = I18n.t("popups.credits.title");
        const message = I18n.t("popups.credits.message");

        m.popupManager?.showPopup(title, message, ModalType_enum.MT_OK, OkButtonType_enum.Green);
    }
}
