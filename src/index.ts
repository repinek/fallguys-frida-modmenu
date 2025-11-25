import "frida-il2cpp-bridge";
import "frida-java-menu";

import { AssemblyHelper } from "./core/assemblyHelper.js";
import { ModuleManager } from "./core/moduleManager.js";

import { ModPreferences } from "./data/modPreferences.js";
import { ObsidianConfig } from "./data/menuConfig.js";
import { Config } from "./data/config.js";

import { GraphicsManagerModule } from "./modules/graphicsManager.js";
import { BuildInfoModule } from "./modules/buildInfo.js";
import { FGDebugModule } from "./modules/fgDebug.js";
import { ModalType_enum, OkButtonType_enum, PopupManagerModule } from "./modules/popupManager.js";
import { TipToeModule } from "./modules/tipToeManager.js";
import { UICanvasModule } from "./modules/uiCanvas.js";

import { I18n } from "./i18n/i18n.js";
import en from "./i18n/localization/en.json";

import { UnityUtils, TeleportManager } from "./utils/unityUtils.js";
import * as javaUtils from "./utils/javaUtils.js";
import { Logger } from "./utils/logger.js";

// WIP CODE !! working to refactor it
/*
My code is kinda structless. Maybe I'll refactor it later, but I'm too lazy since I lost interest in this project
A lot of things has been done already, and I don't even know what else to do. 
frida and il2cpp-bridge doesn't work correctly sometimes, and also I'm too to dumb for some things I guess (?) upd: yes i am lol
honourable mention: Failed to load script: the connection is closed. Thank you for using Frida!
*/

function main() {
    Logger.infoGreen(`Fall Guys Frida Mod Menu ${ModPreferences.VERSION} (${ModPreferences.ENV}), Game Version: ${Il2Cpp.application.version!}`);

    I18n.init();

    AssemblyHelper.init();

    UnityUtils.init();

    ModuleManager.initAll();

    // === Classes ===
    const SceneManager = AssemblyHelper.CoreModule.class("UnityEngine.SceneManagement.SceneManager");

    const LobbyService = AssemblyHelper.MTFGClient.class("FGClient.CatapultServices.LobbyService");
    const GlobalGameStateClient = AssemblyHelper.MTFGClient.class("FGClient.GlobalGameStateClient");
    const ClientGameManager = AssemblyHelper.MTFGClient.class("FGClient.ClientGameManager");
    const FNMMSClientRemoteService = AssemblyHelper.MTFGClient.class("FGClient.FNMMSClientRemoteService");
    const CatapultServicesManager = AssemblyHelper.MTFGClient.class("FGClient.CatapultServices.CatapultServicesManager");

    const CharacterDataMonitor = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
    const MotorFunctionJump = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.Character.MotorFunctionJump");
    const MPGNetMotorTasks = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.MPGNetMotorTasks"); // MPG - The Multiplayer Group
    const CatapultAnalyticsService = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.CatapultAnalyticsService");

    const ObjectiveReachEndZone = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone"); // finish
    const GrabToQualify = AssemblyHelper.TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify"); // crown
    const SpawnableCollectable = AssemblyHelper.TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"); // bubble unity
    const COMMON_ScoringBubble = AssemblyHelper.TheMultiplayerGuys.class("Levels.Progression.COMMON_ScoringBubble"); // bubble creative
    const ScoredButton = AssemblyHelper.TheMultiplayerGuys.class("ScoredButton"); // trigger button unity
    const FakeDoorController = AssemblyHelper.TheMultiplayerGuys.class("Levels.DoorDash.FakeDoorController");
    const CrownMazeDoor = AssemblyHelper.TheMultiplayerGuys.class("Levels.CrownMaze.CrownMazeDoor");
    // const FollowTheLeaderZone = AssemblyHelper.TheMultiplayerGuys.class("Levels.ScoreZone.FollowTheLeader.FollowTheLeaderZone"); // leading light
    // const LevelEditorTriggerZoneActiveBase = WushuLevelEditorRuntime.class("LevelEditorTriggerZoneActiveBase"); // trigger zone creative

    const HttpNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.HttpNetworkHost");
    const WebSocketNetworkHost = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.WebSocketNetworkHost");
    const AnalyticsService = AssemblyHelper.MediatonicCatapultClientSdkRuntime.class("Catapult.Analytics.AnalyticsService");

    // === Methods ===
    const BuildCatapultConfig_method = CatapultServicesManager.method("BuildCatapultConfig");
    const Init_ClientOnly_method = CatapultAnalyticsService.method("Init_ClientOnly", 3);
    const SendEventBatch_method = AnalyticsService.method("SendEventBatch");

    const OnMainMenuDisplayed_method = LobbyService.method("OnMainMenuDisplayed", 1);
    const GameLevelLoaded_method = ClientGameManager.method("GameLevelLoaded", 1);
    const SendMessage_method = MPGNetMotorTasks.method("SendMessage", 1);
    const ProcessMessageReceived_method = FNMMSClientRemoteService.method("ProcessMessageReceived");

    const CheckCharacterControllerData_method = CharacterDataMonitor.method("CheckCharacterControllerData", 1);
    const CanJump_method = MotorFunctionJump.method<boolean>("CanJump");

    // === Cache ===
    let FallGuysCharacterController_Instance: Il2Cpp.Object;
    let CharacterControllerData_Instance: Il2Cpp.Object;
    let JumpMotorFunction_Instance: Il2Cpp.Object;
    let GlobalGameStateClient_Instance: Il2Cpp.Object;
    let ClientGameManager_Instance: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object; // obtaing in GameLevelLoaded

    let reachedMainMenu = false;
    let currentSceneName;

    Logger.info("Loaded il2cpp, assemblies, classes and method pointers");

    // === Fetching Data ===
    let fetchedClientDetails;
    let fetchedModmenuVersion;

    // complicated a little
    // response should be like: {"script_version":"0.0"}
    if (ModPreferences.ENV !== "release") {
        Logger.debug("Skipping mod menu version check in dev/staging");
    } else {
        javaUtils.httpGet(Config.MOD_MENU_VERSION_URL, response => {
            if (!response) {
                Logger.warn("Actual mod menu version can't be fetched");
                Menu.toast(en.toasts.mod_menu_version_not_fetched, 1);
                return;
            }
            try {
                fetchedModmenuVersion = JSON.parse(response);
                if (fetchedModmenuVersion.script_version == ModPreferences.VERSION) {
                    Logger.info("Mod menu is up to date");
                    Menu.toast(en.toasts.mod_menu_version_actual, 1);
                } else {
                    Logger.warn("Mod menu version is outdated, redirecting to download page...");
                    Menu.toast(en.toasts.mod_menu_version_not_fetched, 1);
                    javaUtils.openURL(Config.GITHUB_RELEASES_URL);
                }
            } catch (error: any) {
                Logger.errorThrow(error, "Parse mod menu version");
            }
        });
    }

    // response should be like: {"client_version":"0.0.0","signature":"ABC123"}
    if (Config.USE_SPOOF) {
        javaUtils.httpGet(Config.SPOOF_VERSION_URL, response => {
            if (!response) {
                Logger.warn("Actual server signature can't be fetched, spoof won't be working");
                Menu.toast(en.toasts.signature_not_fetched, 1);
                return;
            }
            try {
                fetchedClientDetails = JSON.parse(response);
            } catch (error: any) {
                Logger.errorThrow(error, "Parse spoof signature");
            }
        });
    }

    Menu.toast(en.messages.menu_will_appear_later, 1);

    // === Helpers ===

    // === Hooks ===
    // Spoofs
    BuildCatapultConfig_method.implementation = function (): Il2Cpp.Object {
        /*
        Change the signature and client version for the request, so that it thinks we are using the latest one.
        Getting it from Config.VERSION_URL, thx to floyzi. You can find it yourself if you want.

        You can also change the platform here, but make sure it exists (otherwise you won't be able to login, mediatonic fixed this)
        Some existing platforms: ps5, pc_steam, pc_standalone (no longer used for official clients), ports3_2...
        More can be found in the CMS and game code
        */
        Logger.hook("BuildCatapultConfig called");
        if (Config.USE_SPOOF && fetchedClientDetails!) {
            const newConfig = this.method<Il2Cpp.Object>("BuildCatapultConfig").invoke(); // create new config

            Config.BuildInfo.originalSignature = newConfig.field<Il2Cpp.String>("ClientVersionSignature").value.content!;
            Config.BuildInfo.spoofedSignature = fetchedClientDetails.signature;
            Config.BuildInfo.spoofedGameVersion = fetchedClientDetails.client_version;

            newConfig.field("ClientVersion").value = Il2Cpp.string(fetchedClientDetails.client_version);
            newConfig.field("ClientVersionSignature").value = Il2Cpp.string(fetchedClientDetails.signature);

            // Spoof platform
            if (Config.BuildInfo.PLATFORM != "android_ega") {
                newConfig.field("Platform").value = Il2Cpp.string(Config.BuildInfo.PLATFORM);
                Logger.debug("Modified signature, client version and platform");
            } else Logger.debug("Modified signature and client version");

            // Custom server
            if (Config.USE_CUSTOM_SERVER) {
                const loginServerHostAlloc = HttpNetworkHost.alloc();
                const gatewayServerHostAlloc = WebSocketNetworkHost.alloc();

                // Adds port to the host string if port > 0
                loginServerHostAlloc.method(".ctor").invoke(Il2Cpp.string(Config.CUSTOM_LOGIN_URL), Config.CUSTOM_LOGIN_PORT);
                // (string host, int port, bool isSecure) — wss if secure, ws otherwise: (isSecure ? "wss://{0}:{1}/ws" : "ws://{0}:{1}/ws");
                gatewayServerHostAlloc.method(".ctor").invoke(Il2Cpp.string(Config.CUSTOM_GATEWAY_URL), Config.CUSTOM_GATEWAY_PORT, Config.IS_GATEWAY_SECURE);

                newConfig.field("LoginServerHost").value = loginServerHostAlloc;
                newConfig.field("GatewayServerHost").value = gatewayServerHostAlloc;

                Logger.debug("Modified Login and Gatewat server hosts");
            }
            return newConfig;
        } else {
            return this.method<Il2Cpp.Object>("BuildCatapultConfig").invoke(); // without any changes
        }
    };

    //@ts-ignore
    Init_ClientOnly_method.implementation = function (serverAddress: Il2Cpp.Object, gatewayConnConfig: Il2Cpp.Object, platformServiceProvider: Il2Cpp.String) {
        Logger.hook("Init_ClientOnly called with args:", serverAddress, gatewayConnConfig, platformServiceProvider);
        if (Config.USE_CUSTOM_SERVER) {
            // refer BuildCatapultConfig_method.implementation
            const analyticsServerHostAlloc = WebSocketNetworkHost.alloc();
            analyticsServerHostAlloc
                .method(".ctor")
                .invoke(Il2Cpp.string(Config.CUSTOM_ANALYTICS_URL), Config.CUSTOM_ANALYTICS_PORT, Config.IS_ANALYTICS_SECURE);

            Logger.debug("Modified Analytics server host");

            return this.method("Init_ClientOnly").invoke(analyticsServerHostAlloc, gatewayConnConfig, platformServiceProvider);
        }
        return this.method("Init_ClientOnly").invoke(serverAddress, gatewayConnConfig, platformServiceProvider);
    };

    // Utils
    OnMainMenuDisplayed_method.implementation = function (event) {
        Logger.hook("OnMainMenuDisplayed Called");

        if (!reachedMainMenu) {
            /*
            sooo, if you load all these assemblies before the menu appears, the game will freeze when entering the main menu. 
            probably, shitcode from menu is a reason, idk.

            you can load the menu here, in this function, and it will wait another 2 seconds in the initMenu function before showing it (bad, but working (not always)), 
            */
            Menu.toast(en.messages.display_menu, 0);

            Menu.waitForInit(initMenu);
            reachedMainMenu = true;
            // if (Config.Toggles.toggleFGDebug) {
            //     FGDebug.enable(); // may cause error, frida & il2cpp-bridge lore, so unstable tbh. UPD: no, i'm just dumb
            // }
        }

        return this.method("OnMainMenuDisplayed", 1).invoke(event);
    };

    GameLevelLoaded_method.implementation = function (ugcLevelHash) {
        Logger.hook("GameLevelLoaded called with args:", ugcLevelHash);

        ClientGameManager_Instance = this;
        GlobalGameStateClient_Instance = GlobalGameStateClient.method<Il2Cpp.Object>("get_Instance").invoke();

        const Scene_Instance = SceneManager.method<Il2Cpp.Object>("GetActiveScene").invoke();
        currentSceneName = Scene_Instance.method<Il2Cpp.String>("get_name").invoke().content; // It's better to check by SceneName, instead round id (and easier lol)

        if (Config.Toggles.toggleHideDoors) {
            const manipulateObjects = (
                type: Il2Cpp.Class, // class of object
                field: string, // getter method name like get_IsFakeDoor
                expectedValue: boolean
            ) => {
                const objectsArray = UnityUtils.findObjectsOfTypeAll(type);

                for (const obj of objectsArray) {
                    const value = obj.method<boolean>(field).invoke();
                    if (value === expectedValue) {
                        const gameObject = obj.method<Il2Cpp.Object>("get_gameObject").invoke();
                        gameObject.method("SetActive").invoke(false);
                    }
                }
            };

            switch (true) {
                case currentSceneName?.includes("FallGuy_DoorDash"):
                    manipulateObjects(FakeDoorController, "get_IsFakeDoor", false);
                    break;

                case currentSceneName?.includes("FallGuy_Crown_Maze_Topdown"):
                    manipulateObjects(CrownMazeDoor, "get_IsBreakable", true);
                    break;

                case currentSceneName?.includes("Fraggle"): // creative codename
                    manipulateObjects(FakeDoorController, "get_IsFakeDoor", false);
                    break;
            }
        }

        return this.method("GameLevelLoaded", 1).invoke(ugcLevelHash);
    };

    SendMessage_method.implementation = function (bypassNetworkLOD) {
        if (Config.Toggles.toggleDontSendFallGuyState) {
            return;
        }
        return this.method("SendMessage", 1).invoke(bypassNetworkLOD);
    };

    SendEventBatch_method.implementation = function () {
        if (Config.Toggles.toggleDisableAnalytics) {
            return;
        }
        return this.method("SendEventBatch").invoke();
    };

    //@ts-ignore
    ProcessMessageReceived_method.implementation = function (jsonMessage: Il2Cpp.String) {
        if (Config.Toggles.toggleShowQueuedPlayers) {
            Logger.debug("ProcessMessageReceived jsonMessage:", jsonMessage.content!);
            const json = JSON.parse(jsonMessage.content!); // .content because it's Il2cpp.String
            if (json.payload) {
                if (json.payload.state == "Queued") {
                    Menu.toast(`Queued Players: ${json.payload.queuedPlayers.toString()}`, 0);
                }
            }
        }
        return this.method("ProcessMessageReceived", 1).invoke(jsonMessage);
    };

    // Physics
    CheckCharacterControllerData_method.implementation = function (character: any) {
        FallGuysCharacterController_Instance = character;
        CharacterControllerData_Instance = character.method("get_Data").invoke(); // get Data instance
        JumpMotorFunction_Instance = character.method("get_JumpMotorFunction").invoke(); // get JumpMotorFunction

        CharacterControllerData_Instance.field("divePlayerSensitivity").value = Config.Toggles.toggle360Dives
            ? 69420
            : Config.DefaultValues.divePlayerSensitivity;

        CharacterControllerData_Instance.field("normalMaxSpeed").value = Config.Toggles.toggleCustomSpeed
            ? Config.CustomValues.normalMaxSpeed
            : Config.DefaultValues.normalMaxSpeed;
        CharacterControllerData_Instance.field("carryMaxSpeed").value = Config.Toggles.toggleCustomSpeed
            ? Config.CustomValues.normalMaxSpeed
            : Config.DefaultValues.carryMaxSpeed;
        CharacterControllerData_Instance.field("grabbingMaxSpeed").value = Config.Toggles.toggleCustomSpeed
            ? Config.CustomValues.normalMaxSpeed
            : Config.DefaultValues.grabbingMaxSpeed;

        CharacterControllerData_Instance.field("maxGravityVelocity").value = Config.Toggles.toggleCustomVelocity
            ? Config.Toggles.toggleNoVelocity
                ? 0 // if enable no velocity
                : Config.Toggles.toggleNegativeVelocity
                  ? -Config.CustomValues.maxGravityVelocity // if enable negative velocity
                  : Config.CustomValues.maxGravityVelocity
            : Config.DefaultValues.maxGravityVelocity;

        CharacterControllerData_Instance.field("diveForce").value = Config.Toggles.toggleCustomDiveForce
            ? Config.CustomValues.diveForce
            : Config.DefaultValues.diveForce;
        CharacterControllerData_Instance.field("airDiveForce").value = Config.Toggles.toggleCustomDiveForce
            ? Config.CustomValues.diveForce / Config.DefaultValues.diveMultiplier
            : Config.DefaultValues.airDiveForce;

        const jumpForce = JumpMotorFunction_Instance.field<Il2Cpp.Object>("_jumpForce").value;
        jumpForce.field("y").value = Config.Toggles.toggleCustomJumpForce ? Config.CustomValues.jumpForce : Config.DefaultValues.jumpForce;

        return true;
    };

    CanJump_method.implementation = function () {
        if (Config.Toggles.toggleAirJump) {
            return true;
        }
        return this.method<boolean>("CanJump").invoke();
    };

    // === Functions ===
    const teleportToFinish = () => {
        if (!TeleportManager.checkCooldown()) return;

        let endZoneObject: Il2Cpp.Object | null;
        let crownObject: Il2Cpp.Object | null;

        const endZoneArray = UnityUtils.findObjectsOfTypeAll(ObjectiveReachEndZone);
        if (endZoneArray.length > 0) {
            endZoneObject = endZoneArray.get(0);
        }

        const crownArray = UnityUtils.findObjectsOfTypeAll(GrabToQualify);
        if (crownArray.length > 0) {
            crownObject = crownArray.get(0);
        }

        const finishObject = endZoneObject! ?? crownObject!;
        if (finishObject) {
            TeleportManager.teleportTo(FallGuysCharacterController_Instance, finishObject);
        } else {
            Menu.toast(en.messages.no_finish, 0);
        }
    };

    const teleportToScore = () => {
        if (!TeleportManager.checkCooldown()) return;

        try {
            const unityBubblesArray = UnityUtils.findObjectsOfTypeAll(SpawnableCollectable);
            const creativeBubblesArray = UnityUtils.findObjectsOfTypeAll(COMMON_ScoringBubble);
            const scoredButtonArray = UnityUtils.findObjectsOfTypeAll(ScoredButton);
            // I'm too lazy to add these sorry
            // const creativeScoreZonesArray = UnityUtils.findObjectsOfTypeAll(LevelEditorTriggerZoneActiveBase);
            // const FollowTheLeaderZonesArray = UnityUtils.findObjectsOfTypeAll(FollowTheLeaderZone)

            // Rest of the function remains the same...
            for (const bubble of unityBubblesArray) {
                if (bubble.method<boolean>("get_Spawned").invoke()) {
                    TeleportManager.teleportTo(FallGuysCharacterController_Instance, bubble);
                    return;
                }
            }

            for (const bubble of creativeBubblesArray) {
                if (bubble.field<number>("_pointsAwarded").value > 0) {
                    const bubbleHandle = bubble.field<Il2Cpp.Object>("_bubbleHandle").value;
                    if (bubbleHandle.field<boolean>("_spawned").value) {
                        TeleportManager.teleportTo(FallGuysCharacterController_Instance, bubble);
                        return;
                    }
                }
            }

            for (const button of scoredButtonArray) {
                if (button.field<boolean>("_isAnActiveTarget").value) {
                    TeleportManager.teleportTo(FallGuysCharacterController_Instance, button);
                    return;
                }
            }

            /*
            for (const scoreZone of creativeScoreZonesArray) {
                if (scoreZone.field<boolean>("_useForPointScoring").value) {
                    if (scoreZone.field<number>("_pointsScored").value > 0) {
                        teleportTo(scoreZone);
                        return;
                    }
                }
            }
    
            for (const scoreZone of FollowTheLeaderZonesArray) {
                teleportTo(scoreZone);
                return;
            }
            */
        } catch (error: any) {
            Logger.errorThrow(error);
        }
        Menu.toast(en.messages.no_score, 0);
    };

    const freezePlayer = {
        enable() {
            if (FallGuysCharacterController_Instance) {
                const characterRigidBody = FallGuysCharacterController_Instance.method<Il2Cpp.Object>("get_RigidBody").invoke();
                characterRigidBody.method("set_isKinematic").invoke(true);
            }
        },
        disable() {
            if (FallGuysCharacterController_Instance) {
                const characterRigidBody = FallGuysCharacterController_Instance.method<Il2Cpp.Object>("get_RigidBody").invoke();
                characterRigidBody.method("set_isKinematic").invoke(false);
            }
        }
    };

    const showServerDetails = () => {
        try {
            if (GlobalGameStateClient_Instance) {
                const networkManager = GlobalGameStateClient_Instance.method<Il2Cpp.Object>("get_NetworkManager").invoke();
                const gameConnection = networkManager.method<Il2Cpp.Object>("get_ConnectionToServer").invoke();

                const hostIPAddr = networkManager.method<Il2Cpp.String>("get_HostIPAddr").invoke().content;
                const hostPortNo = networkManager.method<number>("get_HostPortNo").invoke();
                const rtt = gameConnection.method<number>("CurrentRtt").invoke();

                Menu.toast(`Server: ${hostIPAddr}:${hostPortNo}. Ping: ${rtt}ms`, 0); // little secret, you can ddos these servers, and it's not too hard.
                javaUtils.copyToClipboard(`${hostIPAddr}:${hostPortNo}`);
            } else {
                Menu.toast(en.messages.not_in_the_game, 0);
            }
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    };

    const showGameDetails = () => {
        try {
            if (ClientGameManager_Instance) {
                const round = ClientGameManager_Instance.field<Il2Cpp.Object>("_round").value;
                const roundID = round.method<Il2Cpp.String>("get_Id").invoke().content;
                const seed = ClientGameManager_Instance.method<number>("get_RandomSeed").invoke();
                const eliminatedPlayerCount = ClientGameManager_Instance.field<number>("_eliminatedPlayerCount").value;
                // const initialNumParticipants = ClientGameManager_Instance.field<number>("_initialNumParticipants").value;
                // const allPlayers = ClientGameManager_Instance.method<Il2Cpp.Array<Il2Cpp.Object>>("get_AllPlayers").invoke();

                Menu.toast(`RoundID: ${roundID}, Seed: ${seed}, Eliminated: ${eliminatedPlayerCount}`, 0);
            } else {
                Menu.toast(en.messages.not_in_the_game, 0);
            }
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    };

    const initMenu = () => {
        try {
            const layout = new Menu.ObsidianLayout(ObsidianConfig);
            const composer = new Menu.Composer(en.info.name, en.info.warn, layout);
            composer.icon(Config.MOD_MENU_ICON_URL, "Web");

            const graphicsModule = ModuleManager.get(GraphicsManagerModule);
            const popupManagerModule = ModuleManager.get(PopupManagerModule);
            const buildInfoModule = ModuleManager.get(BuildInfoModule);
            const tipToeModule = ModuleManager.get(TipToeModule);
            const fgDebugModule = ModuleManager.get(FGDebugModule);

            const uiCanvasModule = ModuleManager.get(UICanvasModule);

            if (ModPreferences.ENV === "dev" || ModPreferences.ENV === "staging") {
                Menu.add(
                    // prettier-ignore
                    layout.button("Exit", () => {
                        Menu.toast("Hold for exit", 0)
                    },
                    () => {
                        javaUtils.exitFromApp();
                    })
                );

                Menu.add(
                    layout.button("Debug", () => {
                        Il2Cpp.perform(() => {
                            popupManagerModule?.showPopup("Test Popup", "Message of Test Popup", ModalType_enum.MT_OK, OkButtonType_enum.Green);
                        }, "main"); // From Java.scheduleOnMainThread you need to Il2cpp.perform main!
                    })
                );
                Menu.add(layout.textView(I18n.t("hi.hi")));
            }

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

            Menu.add(layout.toggle(en.menu.functions.toggle_freeze_player, (state: boolean) => (state ? freezePlayer.enable() : freezePlayer.disable())));

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
                layout.button(en.menu.functions.show_tiptoe_path, () =>
                    Il2Cpp.perform(() => {
                        tipToeModule?.removeFakeTipToe();
                    }, "main")
                )
            );

            // === Teleports Tab ===
            const teleports = layout.textView(en.menu.tabs.teleports_tab);
            teleports.gravity = Menu.Api.CENTER;
            Menu.add(teleports);

            Menu.add(layout.button(en.menu.functions.teleport_to_finish_or_crown, teleportToFinish));

            Menu.add(layout.button(en.menu.functions.teleport_to_score, teleportToScore));

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

            Menu.add(layout.button(en.menu.functions.show_game_details, showGameDetails));
            Menu.add(layout.button(en.menu.functions.show_and_copy_server_details, showServerDetails));

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
}

Il2Cpp.perform(main);
