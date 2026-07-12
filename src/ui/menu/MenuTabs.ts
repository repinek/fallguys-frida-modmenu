import { add, Api, CENTER, ObsidianLayout, toast } from "frida-java-menu";
import { Constants } from "../../data/Constants";
import { ModSettings } from "../../data/ModSettings";

import { I18n } from "../../i18n/I18n";

import { JavaUtils } from "../../utils/JavaUtils";

import { MenuPopups } from "./MenuPopups";
import { MenuUtils } from "./MenuUtils";

export class MenuTabs {
    static buildAll(layout: ObsidianLayout) {
        MenuTabs.buildDebugTab(layout);
        MenuTabs.buildMovementTab(layout);
        MenuTabs.buildRoundTab(layout);
        MenuTabs.buildTeleportsTab(layout);
        MenuTabs.buildUtilityTab(layout);
        MenuTabs.buildOtherTab(layout);
    }

    private static buildDebugTab(layout: ObsidianLayout): void {
        /// #if DEV
        const debugtab = layout.textView("Debug");
        debugtab.gravity = CENTER;
        add(debugtab);

        // const debugtext = [
        //     `Frida version: v${Frida.version}`,
        //     `Frida Runtime: ${Script.runtime}`,
        //     `Architecture: ${Process.arch}`,
        //     `Platform: ${Process.platform}`,
        //     `Android version: ${Java.androidVersion}`
        // ];
        // for (const text of debugtext) {
        //     add(layout.textView(text));
        // }

        add(
            layout.button(
                "System.exit",
                () => {
                    toast("Hold for exit", 0);
                },
                () => {
                    // Long Callback
                    JavaUtils.exitFromApp();
                }
            )
        );

        add(
            layout.button(
                "Create Test Popup",
                MenuUtils.run(() => {
                    MenuPopups.showDebugPopup();
                })
            )
        );

        add(
            layout.button(
                "Create test Selection Option Popup",
                MenuUtils.run(() => {
                    MenuPopups.showDebugOptionsPopup();
                })
            )
        );

        add(
            layout.button(
                "Create Test Input Field Popup",
                MenuUtils.run(() => {
                    MenuPopups.showDebugInputPopup();
                })
            )
        );

        // yes i definitely need to other branch it but... sorry
        // add(
        //     layout.button(
        //         "Create Logger",
        //         this.run(() => InGameLogger.createLogger())
        //     )
        // );

        add(layout.textView(I18n.t("hi.hi", "koluska")));
        /// #endif
    }

    private static buildMovementTab(layout: ObsidianLayout): void {
        const m = MenuUtils.modules;
        const movement = layout.textView(I18n.t("menu.tabs.movement"));
        movement.gravity = CENTER;
        add(movement);

        add(
            layout.toggle(I18n.t("menu.functions.360_dives"), (state: boolean) => {
                ModSettings.enable360Dives = state;
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.air_jump"), (state: boolean) => {
                ModSettings.airjump = state;
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.freeze_player"), (state: boolean) => {
                m.characterPhysics?.freezePlayer(state);
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.fallguy_state"), (state: boolean) => {
                ModSettings.dontSendFallGuyState = state;
            })
        );

        add(layout.textView(I18n.t("menu.functions.fallguy_state_warn")));

        add(
            layout.toggle(I18n.t("menu.functions.custom_speed"), (state: boolean) => {
                ModSettings.customSpeed = state;
            })
        );

        add(
            layout.seekbar(I18n.t("menu.functions.speed_val"), 100, 1, (value: number) => {
                ModSettings.normalMaxSpeed = value;
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.custom_gravity"), (state: boolean) => {
                ModSettings.customGravity = state;
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.negative_gravity"), (state: boolean) => {
                ModSettings.negativeGravity = state;
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.no_gravity"), (state: boolean) => {
                ModSettings.noGravity = state;
            })
        );

        add(
            layout.seekbar(I18n.t("menu.functions.gravity_val"), 100, 0, (value: number) => {
                ModSettings.maxGravityVelocity = value;
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.custom_jump_force"), (state: boolean) => {
                ModSettings.customJumpForce = state;
            })
        );

        add(
            layout.seekbar(I18n.t("menu.functions.jump_force_val"), 100, 0, (value: number) => {
                ModSettings.jumpForce = value;
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.custom_dive_force"), (state: boolean) => {
                ModSettings.customDiveForce = state;
            })
        );

        add(
            layout.seekbar(I18n.t("menu.functions.dive_strength_val"), 100, 0, (value: number) => {
                ModSettings.diveForce = value;
            })
        );
    }

    private static buildRoundTab(layout: ObsidianLayout): void {
        const m = MenuUtils.modules;
        const round = layout.textView(I18n.t("menu.tabs.round"));
        round.gravity = CENTER;
        add(round);

        add(
            layout.button(
                I18n.t("menu.functions.hide_doors"),
                MenuUtils.run(() => m.doorManager?.removeRealDoors())
            )
        );

        add(
            layout.button(
                I18n.t("menu.functions.hide_tiptoe"),
                MenuUtils.run(() => m.tipToeManager?.removeFakeTipToe())
            )
        );
    }

    private static buildTeleportsTab(layout: ObsidianLayout): void {
        const m = MenuUtils.modules;
        const teleports = layout.textView(I18n.t("menu.tabs.teleports"));
        teleports.gravity = CENTER;
        add(teleports);

        // prettier-ignore
        add(
            layout.button(
                I18n.t("menu.functions.tp_finish_or_crown"),
                MenuUtils.run(() => m.teleportManager?.teleportToFinish())
            )
        );

        // prettier-ignore
        add(
            layout.button(
                I18n.t("menu.functions.tp_score"),
                MenuUtils.run(() => m.teleportManager?.teleportToScore())
            )
        );
    }

    private static buildUtilityTab(layout: ObsidianLayout): void {
        const m = MenuUtils.modules;
        const utility = layout.textView(I18n.t("menu.tabs.utility"));
        utility.gravity = CENTER;
        add(utility);

        add(
            layout.button(I18n.t("menu.functions.view_names"), () => {
                m.graphicsManager?.toggleNames();
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.custom_fov"), (state: boolean) => {
                ModSettings.customFov = state;
            })
        );

        add(
            layout.seekbar(I18n.t("menu.functions.custom_fov_val"), 180, 1, (value: number) => {
                ModSettings.fov = value;
            })
        );

        // prettier-ignore
        add(
            layout.toggle(
                I18n.t("menu.functions.disable_ui"),
                MenuUtils.run((state: boolean) => m.uiCanvas?.toggleUICanvas(!state))
            )
        );

        // prettier-ignore
        add(
            layout.toggle(
                I18n.t("menu.functions.fgdebug"),
                MenuUtils.run((state: boolean) => m.fgDebug?.toggleFGDebug(state))
            )
        );

        add(
            layout.toggle(I18n.t("menu.functions.disable_analytics"), (state: boolean) => {
                ModSettings.disableAnalytics = state;
            })
        );

        add(
            layout.toggle(I18n.t("menu.functions.queued_players"), (state: boolean) => {
                ModSettings.showQueuedPlayers = state;
            })
        );

        add(
            layout.seekbar(I18n.t("menu.functions.custom_resolution"), 100, 1, (value: number) => {
                ModSettings.resolutionScale = value / 100;
                m.graphicsManager?.changeResolutionScale();
            })
        );

        add(
            layout.button(I18n.t("menu.functions.game_details"), () => {
                m.matchInfo?.showGameDetails();
            })
        );

        add(
            layout.button(I18n.t("menu.functions.server_details"), () => {
                m.matchInfo?.showServerDetails();
            })
        );

        add(
            layout.toggle(
                I18n.t("menu.functions.uwuify"),
                MenuUtils.run((state: boolean) => {
                    ModSettings.uwuifyMode = state;
                    m.uwuify?.toggleUwUify(state);
                })
            )
        );

        add(
            layout.button(
                I18n.t("menu.functions.select_platform"),
                MenuUtils.run(() => MenuPopups.showPlatformPopup())
            )
        );

        add(
            layout.toggle(I18n.t("menu.functions.token_login"), (state: boolean) => {
                ModSettings.tokenLogin = state;
            })
        );
    }

    private static buildOtherTab(layout: ObsidianLayout): void {
        const other = layout.textView(I18n.t("menu.tabs.other"));
        other.gravity = CENTER;
        add(other);

        add(
            layout.button(
                I18n.t("menu.other.language"),
                MenuUtils.run(() => MenuPopups.showLanguagePopup())
            )
        );

        add(layout.button(I18n.t("menu.other.github_url"), () => JavaUtils.openURL(Constants.GITHUB_URL)));
        add(layout.button(I18n.t("menu.other.discord_url"), () => JavaUtils.openURL(Constants.DISCORD_URL)));
        add(layout.button(I18n.t("menu.other.fgtools_mobile_url"), () => JavaUtils.openURL(Constants.FGTOOLS_MOBILE_URL)));

        add(
            layout.button(
                I18n.t("menu.other.credits"),
                MenuUtils.run(() => MenuPopups.showCreditsPopup())
            )
        );

        add(
            layout.button(
                I18n.t("menu.other.changelog"),
                MenuUtils.run(() => MenuPopups.showChangelogPopup())
            )
        );
    }
}
