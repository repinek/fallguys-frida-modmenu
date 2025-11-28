import "frida-il2cpp-bridge";
import "frida-java-menu";

import { AssemblyHelper } from "./core/assemblyHelper.js";
import { ModuleManager } from "./core/moduleManager.js";

import { ModPreferences } from "./data/modPreferences.js";

import { I18n } from "./i18n/i18n.js";
import en from "./i18n/localization/en.json";

import { MenuBuilder } from "./ui/menu.js";

import { UnityUtils } from "./utils/unityUtils.js";
import { Logger } from "./logger/logger.js";
import { UpdateUtils } from "./utils/updateUtils.js";

// WIP CODE !! working to refactor it
/*
My code is kinda structless. Maybe I'll refactor it later, but I'm too lazy since I lost interest in this project
A lot of things has been done already, and I don't even know what else to do. 
frida and il2cpp-bridge doesn't work correctly sometimes, and also I'm too to dumb for some things I guess (?) upd: yes i am lol
honourable mention: Failed to load script: the connection is closed. Thank you for using Frida!
*/

function main() {
    Logger.infoGreen(`Fall Guys Frida Mod Menu ${ModPreferences.VERSION} (${ModPreferences.ENV}), Game Version: ${Il2Cpp.application.version!}`);

    UpdateUtils.checkForUpdate();

    I18n.init();

    AssemblyHelper.init();

    UnityUtils.init();

    ModuleManager.initAll();

    // === Classes ===
    // const LobbyService = AssemblyHelper.MTFGClient.class("FGClient.CatapultServices.LobbyService");

    // === Methods ===
    // const OnMainMenuDisplayed_method = LobbyService.method("OnMainMenuDisplayed", 1);

    // === Cache ===
    // let reachedMainMenu = false;

    Logger.info("Loaded il2cpp, assemblies, classes and method pointers");

    //Menu.toast(en.messages.menu_will_appear_later, 1);

    MenuBuilder.init();
    // === Hooks ===
    // OnMainMenuDisplayed_method.implementation = function (event) {
    //     Logger.hook("OnMainMenuDisplayed Called");

    //     if (!reachedMainMenu) {
    //         /*
    //         sooo, if you load all these assemblies before the menu appears, the game will freeze when entering the main menu.
    //         probably, shitcode from menu is a reason, idk.

    //         you can load the menu here, in this function, and it will wait another 2 seconds in the initMenu function before showing it (bad, but working (not always)),
    //         */
    //         Menu.toast(en.messages.display_menu, 0);

    //         Menu.waitForInit(initMenu);
    //         reachedMainMenu = true;
    //     }

    //     return this.method("OnMainMenuDisplayed", 1).invoke(event);
    // };

    /*
    const initMenu = () => {
        try {
            const layout = new Menu.ObsidianLayout(ObsidianConfig);
            const composer = new Menu.Composer(en.info.name, en.info.warn, layout);
            composer.icon(Config.MOD_MENU_ICON_URL, "Web");

            const buildInfoModule = ModuleManager.get(BuildInfoModule);
            const matchInfoModule = ModuleManager.get(MatchInfoModule);

            const characterPhysicsModule = ModuleManager.get(CharacterPhysicsModule);
            const teleportModule = ModuleManager.get(TeleportManagerModule);

            const doorManagerModule = ModuleManager.get(DoorManagerModule);
            const tipToeModule = ModuleManager.get(TipToeModule);

            const fgDebugModule = ModuleManager.get(FGDebugModule);
            const graphicsModule = ModuleManager.get(GraphicsManagerModule);
            const popupManagerModule = ModuleManager.get(PopupManagerModule);
            const uiCanvasModule = ModuleManager.get(UICanvasModule);

            // === Movement Tab ===
            const movement = layout.textView(en.menu.tabs.movement_tab);
            movement.gravity = Menu.Api.CENTER;
            Menu.add(movement);

            Menu.add(
                layout.toggle(en.menu.functions.toggle_360_dives, (state: boolean) => {
                    Config.Toggles.toggle360Dives = state;
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_air_jump, (state: boolean) => {
                    Config.Toggles.toggleAirJump = state;
                })
            );

            Menu.add(layout.toggle(en.menu.functions.toggle_freeze_player, (state: boolean) => characterPhysicsModule?.freezePlayer(state)));

            Menu.add(
                layout.toggle(en.menu.functions.toggle_dont_send_fallguy_state, (state: boolean) => {
                    Config.Toggles.toggleDontSendFallGuyState = state;
                })
            );

            Menu.add(layout.textView(en.info.fg_state_warn));

            Menu.add(
                layout.toggle(en.menu.functions.toggle_custom_speed, (state: boolean) => {
                    Config.Toggles.toggleCustomSpeed = state;
                })
            );

            Menu.add(
                layout.seekbar(en.menu.functions.custom_speed, 100, 1, (value: number) => {
                    Config.CustomValues.normalMaxSpeed = value;
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_custom_velocity, (state: boolean) => {
                    Config.Toggles.toggleCustomVelocity = state;
                })
            );

            Menu.add(
                layout.seekbar(en.menu.functions.vertical_gravity_velocity, 100, 0, (value: number) => {
                    Config.CustomValues.maxGravityVelocity = value;
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_negative_velocity, (state: boolean) => {
                    Config.Toggles.toggleNegativeVelocity = state;
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_no_vertical_velocity, (state: boolean) => {
                    Config.Toggles.toggleNoVelocity = state;
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_custom_jump_strength, (state: boolean) => {
                    Config.Toggles.toggleCustomJumpForce = state;
                })
            );

            Menu.add(
                layout.seekbar(en.menu.functions.jump_strength, 100, 1, (value: number) => {
                    Config.CustomValues.jumpForce = value;
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_custom_dive_strength, (state: boolean) => {
                    Config.Toggles.toggleCustomDiveForce = state;
                })
            );

            Menu.add(
                layout.seekbar(en.menu.functions.dive_strength, 100, 1, (value: number) => {
                    Config.CustomValues.diveForce = value;
                })
            );

            // === Round Tab ===
            const round_tab = layout.textView(en.menu.tabs.round_tab);
            round_tab.gravity = Menu.Api.CENTER;
            Menu.add(round_tab);

            Menu.add(
                layout.toggle(en.menu.functions.hide_real_doors, (state: boolean) => {
                    Config.Toggles.toggleHideDoors = state;
                })
            );

            Menu.add(
                layout.button("hide real doors", () => {
                    Il2Cpp.perform(() => {
                        doorManagerModule?.removeRealDoors();
                    }, "main");
                })
            );

            Menu.add(
                layout.button(en.menu.functions.show_tiptoe_path, () => {
                    Il2Cpp.perform(() => {
                        tipToeModule?.removeFakeTipToe();
                    }, "main");
                })
            );

            // === Teleports Tab ===
            const teleports = layout.textView(en.menu.tabs.teleports_tab);
            teleports.gravity = Menu.Api.CENTER;
            Menu.add(teleports);

            Menu.add(layout.button(en.menu.functions.teleport_to_finish_or_crown, () => teleportModule?.teleportToFinish()));

            Menu.add(layout.button(en.menu.functions.teleport_to_score, () => teleportModule?.teleportToScore()));

            // === Utility Tab ===
            const utility = layout.textView(en.menu.tabs.utility_tab);
            utility.gravity = Menu.Api.CENTER;
            Menu.add(utility);

            Menu.add(
                layout.button(en.menu.functions.toggle_view_names, () => {
                    graphicsModule?.toggleNames();
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_custom_fov, (state: boolean) => {
                    Config.Toggles.toggleCustomFov = state;
                })
            );

            Menu.add(
                layout.seekbar(en.menu.functions.custom_fov, 180, 1, (value: number) => {
                    if (Config.Toggles.toggleCustomFov) {
                        graphicsModule?.changeFOV(value);
                    }
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_disable_ui, (state: boolean) =>
                    Il2Cpp.perform(() => {
                        uiCanvasModule?.toggleUICanvas(!state);
                    }, "main")
                )
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_fgdebug, (state: boolean) =>
                    Il2Cpp.perform(() => {
                        fgDebugModule?.toggleFGDebug(state);
                    }, "main")
                )
            );

            Menu.add(
                layout.toggle(en.menu.functions.toggle_disable_analytics, (state: boolean) => {
                    Config.Toggles.toggleDisableAnalytics = state;
                })
            );

            Menu.add(
                layout.toggle(en.menu.functions.show_number_of_queued_players, (state: boolean) => {
                    Config.Toggles.toggleShowQueuedPlayers = state;
                })
            );

            Menu.add(
                layout.seekbar(en.menu.functions.custom_resolution, 100, 1, (value: number) => {
                    Config.CustomValues.ResolutionScale = value / 100;
                    graphicsModule?.changeResolutionScale();
                })
            );

            Menu.add(
                layout.button(en.menu.functions.show_game_details, () => {
                    matchInfoModule?.showGameDetails();
                })
            );
            Menu.add(
                layout.button(en.menu.functions.show_and_copy_server_details, () => {
                    matchInfoModule?.showServerDetails();
                })
            );

            // === Links Tab ===
            const links = layout.textView(en.menu.tabs.links_tab);
            links.gravity = Menu.Api.CENTER;
            Menu.add(links);

            Menu.add(layout.button(en.info.github_url, () => javaUtils.openURL(Config.GITHUB_URL)));
            Menu.add(layout.button(en.info.discord_url, () => javaUtils.openURL(Config.DISCORD_INVITE_URL)));

            // === Build Info Tab ===
            // TODO: correct this with i18n and if
            const info = layout.textView(en.menu.tabs.build_info_tab);
            info.gravity = Menu.Api.CENTER;
            Menu.add(info);

            Menu.add(layout.textView("Game info"));
            Menu.add(layout.textView(buildInfoModule!.getShortString()));
            Menu.add(layout.textView(`${en.info.unity_version} ${Il2Cpp.unityVersion}`));
            Menu.add(layout.textView(`${en.info.package_name} ${Il2Cpp.application.identifier}`));

            Menu.add(layout.textView("Mod Menu info"));
            Menu.add(layout.textView(`${en.info.mod_menu_version} ${ModPreferences.VERSION}`));
            Menu.add(layout.textView(`${en.info.mod_menu_version} ${ModPreferences.ENV}`));

            Menu.add(layout.textView("Spoof info"));
            Menu.add(layout.textView(`${en.info.is_spoofed} ${Config.USE_SPOOF}`));
            if (Config.USE_SPOOF) Menu.add(layout.textView(`${en.info.spoofed_game_version} ${Config.BuildInfo.spoofedGameVersion}`));
            Menu.add(layout.textView(`${en.info.original_signature} ${Config.BuildInfo.originalSignature}`));
            if (Config.USE_SPOOF) Menu.add(layout.textView(`${en.info.spoofed_signature} ${Config.BuildInfo.spoofedSignature}`));
            Menu.add(layout.textView(`${en.info.platform} ${Config.BuildInfo.PLATFORM}`));

            const author = layout.textView(en.info.author);
            author.gravity = Menu.Api.CENTER;
            Menu.add(author);

            const specialThanks = layout.textView(en.info.special_thanks);
            specialThanks.gravity = Menu.Api.CENTER;
            Menu.add(specialThanks);

            Java.scheduleOnMainThread(() => {
                setTimeout(() => {
                    composer.show();
                }, 2000);
            });
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    };
    */
}

Il2Cpp.perform(main);
