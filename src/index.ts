import "frida-il2cpp-bridge";
import "frida-java-menu";
import Java from "frida-java-bridge";
import { openURL, copyToClipboard, httpGet } from "./utils.js";
import { obsidianConfig } from "./menuConfig.js";
import { modPreferences } from "./modPreferences.js";
import { Config } from "./config.js";

import en from "./localization/en.json";

// My code is kinda structless. Maybe I'll refactor it later, but I'm too lazy since I lost interest in this project
// A lot of things has been done already, and I don't even know what else to do. 
// frida and il2cpp-bridge doesn't work correctly sometimes, and also I'm too to dumb for some things I guess (?) upd: yes i am lol
// honourable mention: Failed to load script: the connection is closed. Thank you for using Frida!

function main() {
    // === Assemblies ===
    const TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image; // FG.Common namespace
    const CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    const MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image; // FGClient namespace
    // const WushuLevelEditorRuntime = Il2Cpp.domain.assembly("Wushu.LevelEditor.Runtime").image; // creative logic
    const MediatonicCatapultClientSdkRuntime = Il2Cpp.domain.assembly("Mediatonic.Catapult.ClientSdk.Runtime").image; // connection

    // === Classes === 
    const Resources = CoreModule.class("UnityEngine.Resources");
    const Vector3class = CoreModule.class("UnityEngine.Vector3");
    const SceneManager = CoreModule.class("UnityEngine.SceneManagement.SceneManager");
    const Camera = CoreModule.class("UnityEngine.Camera");

    const BuildInfo = TheMultiplayerGuys.class("FG.Common.BuildInfo");
    const GraphicsSettings = MTFGClient.class("FGClient.GraphicsSettings");
    const PlayerInfoHUDBase = MTFGClient.class("FGClient.PlayerInfoHUDBase"); // ShowNames field storing here
    const UICanvas = MTFGClient.class("FGClient.UI.Core.UICanvas");
    const MainMenuViewModel = MTFGClient.class("FGClient.MainMenuViewModel");
    const LobbyService = MTFGClient.class("FGClient.CatapultServices.LobbyService");
    const GlobalGameStateClient = MTFGClient.class("FGClient.GlobalGameStateClient");
    const ClientGameManager = MTFGClient.class("FGClient.ClientGameManager");
    const AFKManager = MTFGClient.class("FGClient.AFKManager");
    const FNMMSClientRemoteService = MTFGClient.class("FGClient.FNMMSClientRemoteService");
    const CatapultServicesManager = MTFGClient.class("FGClient.CatapultServices.CatapultServicesManager");

    const PopupManager = MTFGClient.class("FGClient.UI.PopupManager");
    const LocaliseOption = MTFGClient.class("FGClient.UI.UIModalMessage/LocaliseOption");
    const ModalType = MTFGClient.class("FGClient.UI.UIModalMessage/ModalType");
    const OkButtonType = MTFGClient.class("FGClient.UI.UIModalMessage/OKButtonType");
    
    // refer createPopup()
    const ModalMessageData = MTFGClient.class("FGClient.UI.ModalMessageData");
    const PopupInteractionType = MTFGClient.class("FGClient.UI.PopupInteractionType");
    

    const CharacterDataMonitor = TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
    const MotorFunctionJump = TheMultiplayerGuys.class("FG.Common.Character.MotorFunctionJump");
    const MPGNetMotorTasks = TheMultiplayerGuys.class("FG.Common.MPGNetMotorTasks"); // MPG - The Multiplayer Group 
    const CatapultAnalyticsService = TheMultiplayerGuys.class("FG.Common.CatapultAnalyticsService");

    const DebugClass = TheMultiplayerGuys.class("GvrFPS"); // FGDebug

    const ObjectiveReachEndZone = TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone"); // finish
    const GrabToQualify = TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify"); // crown
    const SpawnableCollectable = TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"); // bubble unity
    const COMMON_ScoringBubble = TheMultiplayerGuys.class("Levels.Progression.COMMON_ScoringBubble"); // bubble creative
    const ScoredButton = TheMultiplayerGuys.class("ScoredButton"); // trigger button unity
    const TipToe_Platform = TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");
    const FakeDoorController = TheMultiplayerGuys.class("Levels.DoorDash.FakeDoorController");
    const CrownMazeDoor = TheMultiplayerGuys.class("Levels.CrownMaze.CrownMazeDoor");
    // const FollowTheLeaderZone = TheMultiplayerGuys.class("Levels.ScoreZone.FollowTheLeader.FollowTheLeaderZone"); // leading light
    // const LevelEditorTriggerZoneActiveBase = WushuLevelEditorRuntime.class("LevelEditorTriggerZoneActiveBase"); // trigger zone creative

    const HttpNetworkHost = MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.HttpNetworkHost");
    const WebSocketNetworkHost = MediatonicCatapultClientSdkRuntime.class("Catapult.Network.Connections.Config.WebSocketNetworkHost");
    const AnalyticsService = MediatonicCatapultClientSdkRuntime.class("Catapult.Analytics.AnalyticsService");
    const Show_method = PopupManager.method("Show", 3);
    const Show_method_overload = Show_method.overload("FGClient.UI.PopupInteractionType", "FGClient.UI.ModalMessageData", "FGClient.UI.UIModalMessage.ModalMessageFailedToShow");
            
    // === Methods === 
    const BuildCatapultConfig_method = CatapultServicesManager.method("BuildCatapultConfig");
    const Init_ClientOnly_method = CatapultAnalyticsService.method("Init_ClientOnly", 3);
    const SendEventBatch_method = AnalyticsService.method("SendEventBatch");
    const CheckAntiCheatClientServiceForError_method = MainMenuViewModel.method<boolean>("CheckAntiCheatClientServiceForError");

    const set_fieldOfView_method = Camera.method("set_fieldOfView", 1);
    const get_TargetFrameRate_method = GraphicsSettings.method("get_TargetFrameRate");
    const set_TargetFrameRate_method = GraphicsSettings.method("set_TargetFrameRate", 1);
    const get_ResolutionScale_method = GraphicsSettings.method("get_ResolutionScale");
    const set_ResolutionScale_method = GraphicsSettings.method("set_ResolutionScale", 1);
    const SetShowPlayerNamesByDefault_method = PlayerInfoHUDBase.method("SetShowPlayerNamesByDefault", 1);

    const StartAFKManager_method = AFKManager.method("Start");
    const OnMainMenuDisplayed_method = LobbyService.method("OnMainMenuDisplayed", 1);
    const GameLevelLoaded_method = ClientGameManager.method("GameLevelLoaded", 1);
    const SendMessage_method = MPGNetMotorTasks.method("SendMessage", 1);
    const ProcessMessageReceived_method = FNMMSClientRemoteService.method("ProcessMessageReceived");
    const BuildInfo_OnEnable_method = BuildInfo.method("OnEnable");

    const CheckCharacterControllerData_method = CharacterDataMonitor.method("CheckCharacterControllerData", 1);
    const CanJump_method = MotorFunctionJump.method<boolean>("CanJump");

    // === Cache === 
    let FallGuysCharacterController_Instance: Il2Cpp.Object;
    let CharacterControllerData_Instance: Il2Cpp.Object;
    let JumpMotorFunction_Instance: Il2Cpp.Object;
    let FGDebug_Instance: Il2Cpp.Object;
    let GraphicsSettings_Instance: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object; // obtaing in get_ResolutionScale
    let GlobalGameStateClient_Instance: Il2Cpp.Object;
    let ClientGameManager_Instance: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object; // obtaing in GameLevelLoaded
    let Camera_Instance: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object; // obtaing in set_fieldOfView
    let UICanvas_Instance: Il2Cpp.Object;

    let fetchedClientDetails;
    let fetchedModmenuVersion;
    let reachedMainMenu = false;
    let currentSceneName;
    let showPlayerNames: boolean;
    let lastTeleportTime = 0;

    console.log(en.debug_messages.loaded);
    
    if (Config.USE_SPOOF)
    {
        httpGet(Config.SPOOF_VERSION_URL, (response) => {
            try {
                fetchedClientDetails = JSON.parse(response);
                console.log(en.debug_messages.signature_fetched, response);
            } catch (error: any) {
                console.log("error:", error);
                Menu.toast(en.debug_messages.signature_not_fetched, 1)
            }
        });
    }

    httpGet(Config.VERSION_URL, (response) => {
        try {
            fetchedModmenuVersion = JSON.parse(response);
            console.log(en.debug_messages.version_fetched, response);
            if (fetchedModmenuVersion.version == Il2Cpp.application.version!)
                Menu.toast(en.debug_messages.version_actual, 1);
            else {
                Menu.toast(en.debug_messages.version_not_actual, 1);
                openURL(Config.GITHUB_RELEASES_URL);
            };
        } catch (error: any) {
            console.log("error:", error);
            Menu.toast(en.debug_messages.version_not_fetched, 1)
        }
    });

    Menu.toast(en.messages.menu_will_appear_later, 1);

    // === Helpers === 
    const findObjectsOfTypeAll = (klass: Il2Cpp.Class) => {
        return Resources.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1).invoke(klass.type.object);
    };

    const teleportTo = (target: Il2Cpp.Object) => {
    const objectVector3Pos = target
        .method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method<Il2Cpp.Object>("get_position")
        .invoke();

    FallGuysCharacterController_Instance
        .method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method<Il2Cpp.Object>("set_position")
        .invoke(objectVector3Pos);
    };

    const checkTeleportCooldown = () => {
        // Check if enough time has passed since the last teleport
        const currentTime = Date.now();
        if (currentTime - lastTeleportTime < Config.TELEPORT_COOLDOWN) {
            Menu.toast(`Please wait ${((Config.TELEPORT_COOLDOWN - (currentTime - lastTeleportTime)) / 1000).toFixed(1)} seconds before teleporting again!`, 0);
            return false;
        };
        lastTeleportTime = currentTime;
        return true;
    };

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
                console.log(en.debug_messages.login_spoofed_with_platform);
            } else
                console.log(en.debug_messages.login_spoofed);
            
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
                
                console.log(en.debug_messages.server_spoofed);
            }

            return newConfig; 
        } else {
            return this.method<Il2Cpp.Object>("BuildCatapultConfig").invoke(); // without any changes
        };
    };
    
    //@ts-ignore
    Init_ClientOnly_method.implementation = function (serverAddress: Il2Cpp.Object, gatewayConnConfig: Il2Cpp.Object, platformServiceProvider: Il2Cpp.String) {
        if (Config.USE_CUSTOM_SERVER) {
            // refer BuildCatapultConfig hook
            const analyticsServerHostAlloc = WebSocketNetworkHost.alloc();
            analyticsServerHostAlloc.method(".ctor").invoke(Il2Cpp.string(Config.CUSTOM_ANALYTICS_URL), Config.CUSTOM_ANALYTICS_PORT, Config.IS_ANALYTICS_SECURE);

            return this.method("Init_ClientOnly").invoke(analyticsServerHostAlloc, gatewayConnConfig, platformServiceProvider);
        }
        return this.method("Init_ClientOnly").invoke(serverAddress, gatewayConnConfig, platformServiceProvider);
    }; 

    // Bypass permanent ban
    // Temporary bans cannot be bypassed, but permanent bans can be loool
    CheckAntiCheatClientServiceForError_method.implementation = function () {
        /* 
        Called when trying to join matchmaking.
        Returns true if: 
            - no AntiCheatClient Instance
            - AntiCheatClient::get_AllowOnlinePlay returned false 
              (Since you are banned AllowOnlinePlay will be set to false)
        If true: it won't be let matchmake you and will call ShowAntiCheatPopup method (also refer show_method_overload.implementation for more about ShowAntiCheatPopup)
        So, we just return false here
        */
        return false; 
    };

    Show_method_overload.implementation = function (PopupInteractionTypeValue, ModalMessageDataValue, ModalMessageFailedToShow) {
        ModalMessageDataValue = ModalMessageDataValue as Il2Cpp.Object;

        if (ModalMessageData.field<Il2Cpp.String>("Title").value.content == "anticheat_error_title") {
            /*
            ShowAntiCheatPopup will called by _CheckRestrictedGameAccess_d__69::MoveNext corutine
            CheckRestrictedGameAccess called by OnLoginSuccessful (When you login in)
            */ 
            const NotLocalised_Option = LocaliseOption.field<Il2Cpp.ValueType>("NotLocalised").value;

            ModalMessageData.field<Il2Cpp.String>("Title").value = Il2Cpp.string(en.messages.account_banned);
            ModalMessageData.field<Il2Cpp.String>("Message").value = Il2Cpp.string(en.messages.account_banned_desc);
            ModalMessageData.field<Il2Cpp.ValueType>("LocaliseTitle").value = NotLocalised_Option; 
            ModalMessageData.field<Il2Cpp.ValueType>("LocaliseMessage").value = NotLocalised_Option; 
            ModalMessageData.field<Il2Cpp.ValueType>("ModalType").value = ModalType.field<Il2Cpp.ValueType>(ModalType_enum.MT_OK).value;
            ModalMessageData.field<Il2Cpp.ValueType>("OkButtonType").value = OkButtonType.field<Il2Cpp.ValueType>(OkButtonType_enum.Green).value;
        };

        const this_method = this.method("Show", 3).overload(PopupInteractionType, ModalMessageData, "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"); // for instance
        return this_method.invoke(PopupInteractionTypeValue, ModalMessageDataValue, ModalMessageFailedToShow);
    };

    // Graphics 
    set_fieldOfView_method.implementation = function (value) {
        Camera_Instance = this;
        if (Config.Toggles.toggleCustomFov) {
            value = Config.CustomValues.FOV;
        } 
        return this.method("set_fieldOfView", 1).invoke(value);
    };

    get_TargetFrameRate_method.implementation = function () {
        return 1337; // litterally unlimited, because it's linked to the screen refresh rate
    };

    set_TargetFrameRate_method.implementation = function (fps) {
        return this.method("set_TargetFrameRate", 1).invoke(1337);
    };

    get_ResolutionScale_method.implementation = function () {
        GraphicsSettings_Instance = this; // often gc.choose causes crashes
        return Config.CustomValues.ResolutionScale;
    };

    set_ResolutionScale_method.implementation = function (scale) {
        return this.method("set_ResolutionScale", 1).invoke(Config.CustomValues.ResolutionScale); 
    };

    SetShowPlayerNamesByDefault_method.implementation = function (value) {
        showPlayerNames = value as boolean;
        return this.method("SetShowPlayerNamesByDefault", 1).invoke(value);
    };

    // Utils 
    StartAFKManager_method.implementation = function () {
        return; // anti-afk
    };

    OnMainMenuDisplayed_method.implementation = function (event) {
        console.log("OnMainMenuDisplayed Called!");

        if (!reachedMainMenu) {
            /*
            sooo, if you load all these assemblies before the menu appears, the game will freeze when entering the main menu. 
            probably, shitcode from menu is a reason, idk.

            you can load the menu here, in this function, and it will wait another 2 seconds in the initMenu function before showing it (bad, but working (not always)), 
            */
            Menu.toast(en.messages.display_menu, 0);

            Menu.waitForInit(initMenu);
            reachedMainMenu = true;
            if (Config.Toggles.toggleFGDebug) {
                FGDebug.enable(); // may cause error, frida & il2cpp-bridge lore, so unstable tbh
            }
        }

        return this.method("OnMainMenuDisplayed", 1).invoke(event);
    };

    GameLevelLoaded_method.implementation = function (ugcLevelHash) {
        console.log("GameLevelLoaded called!");

        ClientGameManager_Instance = this;
        GlobalGameStateClient_Instance = GlobalGameStateClient.method<Il2Cpp.Object>("get_Instance").invoke();

        const Scene_Instance = SceneManager.method<Il2Cpp.Object>("GetActiveScene").invoke();
        currentSceneName = Scene_Instance.method<Il2Cpp.String>("get_name").invoke().content; // It's better to check by SceneName, instead round id (and easier lol)

        if (Config.Toggles.toggleHideDoors) {
            const manipulateObjects = (
                type: Il2Cpp.Class, // class of object
                field: string, // getter method name like get_IsFakeDoor 
                expectedValue: boolean,
            ) => {
                const objectsArray = findObjectsOfTypeAll(type);
        
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
        };
        return this.method("SendMessage", 1).invoke(bypassNetworkLOD);
    };

    SendEventBatch_method.implementation = function () {
        if (Config.Toggles.toggleDisableAnalytics) {
            return;
        };
        return this.method("SendEventBatch").invoke();
    };

    //@ts-ignore, code from wiki snippets btw lol
    ProcessMessageReceived_method.implementation = function (jsonMessage: Il2Cpp.String) {
        if (Config.Toggles.toggleShowQueuedPlayers) {
            console.log(jsonMessage.content);
            const json = JSON.parse(jsonMessage.content!); // .content because it's Il2cpp.String
            
            if (json.payload) {
                if (json.payload.state == "Queued") { // if in queue 
                    Menu.toast(`Queued Players: ${json.payload.queuedPlayers.toString()}`, 0);
                }
            }
        }

        return this.method("ProcessMessageReceived", 1).invoke(jsonMessage);
    };

    BuildInfo_OnEnable_method.implementation = function () {
        Config.BuildInfo.gameVersion = Il2Cpp.application.version!;
        Config.BuildInfo.unityVersion = Il2Cpp.unityVersion;
        Config.BuildInfo.buildNumber = this.field<Il2Cpp.String>("buildNumber").value.content!;
        Config.BuildInfo.buildDate = this.field<Il2Cpp.String>("buildDate").value.content!;
        // other fields are useless, if you want you can grab it too

        return this.method("OnEnable").invoke();
    };

    // Physics 
    CheckCharacterControllerData_method.implementation = function (character: any) {
        FallGuysCharacterController_Instance = character;
        CharacterControllerData_Instance = character.method("get_Data").invoke(); // get Data instance
        JumpMotorFunction_Instance = character.method("get_JumpMotorFunction").invoke(); // get JumpMotorFunction 
    
        CharacterControllerData_Instance.field("divePlayerSensitivity").value = Config.Toggles.toggle360Dives ? 69420 : Config.DefaultValues.divePlayerSensitivity;

        CharacterControllerData_Instance.field("normalMaxSpeed").value = Config.Toggles.toggleCustomSpeed ? Config.CustomValues.normalMaxSpeed : Config.DefaultValues.normalMaxSpeed;
        CharacterControllerData_Instance.field("carryMaxSpeed").value = Config.Toggles.toggleCustomSpeed ? Config.CustomValues.normalMaxSpeed : Config.DefaultValues.carryMaxSpeed;
        CharacterControllerData_Instance.field("grabbingMaxSpeed").value = Config.Toggles.toggleCustomSpeed ? Config.CustomValues.normalMaxSpeed : Config.DefaultValues.grabbingMaxSpeed;

        CharacterControllerData_Instance.field("maxGravityVelocity").value = Config.Toggles.toggleCustomVelocity
            ? Config.Toggles.toggleNoVelocity 
                ? 0 // if enable no velocity
                : Config.Toggles.toggleNegativeVelocity
                  ? -Config.CustomValues.maxGravityVelocity // if enable negative velocity
                  : Config.CustomValues.maxGravityVelocity
            : Config.DefaultValues.maxGravityVelocity;
        
        CharacterControllerData_Instance.field("diveForce").value = Config.Toggles.toggleCustomDiveForce ? Config.CustomValues.diveForce : Config.DefaultValues.diveForce;
        CharacterControllerData_Instance.field("airDiveForce").value = Config.Toggles.toggleCustomDiveForce ? Config.CustomValues.diveForce / Config.DefaultValues.diveMultiplier : Config.DefaultValues.airDiveForce;

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
    const FGDebug = {
        enable() {
            Config.Toggles.toggleFGDebug = true;

            if (!reachedMainMenu) {
                return; // it will enable after hook onMainMenuDisplayed
            }

            try {
                FGDebug_Instance = findObjectsOfTypeAll(DebugClass).get(0); // find object with debug class

                const localScale = Vector3class.alloc().unbox();
                localScale.method(".ctor", 3).invoke(0.4, 0.4, 0.4); // new scale (original is 0.6, too big)

                FGDebug_Instance
                .method<Il2Cpp.Object>("get_transform").invoke()
                .method<Il2Cpp.Object>("set_localScale").invoke(localScale);

                const gameObject = FGDebug_Instance.method<Il2Cpp.Object>("get_gameObject").invoke();
                gameObject.method("SetActive").invoke(true);
            } catch (error: any) {
                Menu.toast(error.stack, 1);
                console.error(error.stack);
            }
        },
        disable() {
            Config.Toggles.toggleFGDebug = false;
            FGDebug_Instance = findObjectsOfTypeAll(DebugClass).get(0);
            if (FGDebug_Instance) {
                const gameObject = FGDebug_Instance.method<Il2Cpp.Object>("get_gameObject").invoke();
                gameObject.method("SetActive").invoke(false);
            }
        },
    };

    const UICanvas_util = {
        enable() {
            UICanvas_Instance = findObjectsOfTypeAll(UICanvas).get(0);
            if (UICanvas_Instance) {
                UICanvas_Instance.method("SetEnabled").invoke(true);
            }
        },
        disable() {
            UICanvas_Instance = findObjectsOfTypeAll(UICanvas).get(0);
            if (UICanvas_Instance) {
                UICanvas_Instance.method("SetEnabled").invoke(false);
            }
        }
    };

    const changeFov = (value: number) => {
        if (Camera_Instance) {
            Config.CustomValues.FOV = value;
            Camera_Instance.method("set_fieldOfView", 1).invoke(value);
        }
    };

    const teleportToFinish = () => {
        if (!checkTeleportCooldown()) return;
        
        let endZoneObject: Il2Cpp.Object | null;
        let crownObject: Il2Cpp.Object | null;
    
        const endZoneArray = findObjectsOfTypeAll(ObjectiveReachEndZone);
        if (endZoneArray.length > 0) {
            endZoneObject = endZoneArray.get(0);
        }
    
        const crownArray = findObjectsOfTypeAll(GrabToQualify);
        if (crownArray.length > 0) {
            crownObject = crownArray.get(0);
        }
    
        const finishObject = endZoneObject! ?? crownObject!;
        if (finishObject) {
            teleportTo(finishObject);
        } else {
            Menu.toast(en.messages.no_finish, 0);
        }
    };

    const teleportToScore = () => {
        if (!checkTeleportCooldown()) return;
        
        try {
            const unityBubblesArray = findObjectsOfTypeAll(SpawnableCollectable);
            const creativeBubblesArray = findObjectsOfTypeAll(COMMON_ScoringBubble);
            const scoredButtonArray = findObjectsOfTypeAll(ScoredButton);
            // I'm too lazy to add these sorry
            // const creativeScoreZonesArray = findObjectsOfTypeAll(LevelEditorTriggerZoneActiveBase);
            // const FollowTheLeaderZonesArray = findObjectsOfTypeAll(FollowTheLeaderZone) 
    
            // Rest of the function remains the same...
            for (const bubble of unityBubblesArray) {
                if (bubble.method<boolean>("get_Spawned").invoke()) {
                    teleportTo(bubble);
                    return;
                }
            }
    
            for (const bubble of creativeBubblesArray) {
                if (bubble.field<number>("_pointsAwarded").value > 0) {
                    let bubbleHandle = bubble.field<Il2Cpp.Object>("_bubbleHandle").value;
                    if (bubbleHandle.field<boolean>("_spawned").value) {
                        teleportTo(bubble);
                        return;
                    }
                }
            }
    
            for (const button of scoredButtonArray) {
                if (button.field<boolean>("_isAnActiveTarget").value) {
                    teleportTo(button);
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
            console.error(error.stack);
            Menu.toast(error.stack, 0);
        }
        Menu.toast(en.messages.no_score, 0);
    };

    const freezePlayer = {
        enable() {
            if (FallGuysCharacterController_Instance) {
                const characterRigidBody = FallGuysCharacterController_Instance.method<Il2Cpp.Object>("get_RigidBody").invoke();
                characterRigidBody.method("set_isKinematic").invoke(true);
            };
        },
        disable() {
            if (FallGuysCharacterController_Instance) {
                const characterRigidBody = FallGuysCharacterController_Instance.method<Il2Cpp.Object>("get_RigidBody").invoke();
                characterRigidBody.method("set_isKinematic").invoke(false);
            };
        }
    };
    
    const changeResolutionScale = () => {
        try {
            console.log(en.debug_messages.change_resolution, Config.CustomValues.ResolutionScale);
            GraphicsSettings_Instance.method("set_ResolutionScale", 1).invoke(Config.CustomValues.ResolutionScale);
            /*
            i wanted to make this value changeable in the game, but unfortunately 
            calling ResolutionScaling::UpdateResolutionScaleStatus() just crashes the game for now.
            */
        } catch (error: any) {
            Menu.toast(error.stack, 1); 
            console.error(error.stack);
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

                console.log(`Server: ${hostIPAddr}:${hostPortNo}\nPing: ${rtt}ms`);
                Menu.toast(`Server: ${hostIPAddr}:${hostPortNo}. Ping: ${rtt}ms`, 0); // little secret, you can ddos these servers, and it's not too hard.
                copyToClipboard(`${hostIPAddr}:${hostPortNo}`);
            } else {
                Menu.toast(en.messages.not_in_the_game, 0);
            }
        } catch (error: any) {
            Menu.toast(en.messages.not_in_the_game, 0);
            console.error(error.stack);
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

                console.log(`RoundID: ${roundID}, Seed: ${seed}, Eliminated: ${eliminatedPlayerCount}`);
                Menu.toast(`RoundID: ${roundID}, Seed: ${seed}, Eliminated: ${eliminatedPlayerCount}`, 0);
            } else {
                Menu.toast(en.messages.not_in_the_game, 0);
            }
        } catch (error: any) {
            Menu.toast(en.messages.not_in_the_game, 0);
            console.error(error.stack);
        }
    };

    const showTipToePath = () => {
        try {
            const tiptoePlatformArray = findObjectsOfTypeAll(TipToe_Platform);
            for (const tiptoe of tiptoePlatformArray) {
                const tiptoeStatus = tiptoe.method<boolean>("get_IsFakePlatform").invoke();
                if (tiptoeStatus) { // if fake
                    const tiptoeObject = tiptoe.method<Il2Cpp.Object>("get_gameObject").invoke();
                    tiptoeObject.method("SetActive").invoke(false);
                }
            }
        } catch (error: any) {
            Menu.toast(error.stack, 0);
            console.error(error.stack);
        }
    };
    
    enum ModalType_enum {
        MT_OK = "MT_OK",
        MT_OK_CANCEL = "MT_OK_CANCEL",
        MT_BLOCKING = "MT_BLOCKING",
        MT_WAIT_FOR_EVENT = "MT_WAIT_FOR_EVENT",
        MT_NO_BUTTONS = "MT_NO_BUTTONS"
    };

    enum OkButtonType_enum {
        Blue = "Default",
        Red = "Disruptive",
        Green = "Positive",
        Yellow = "CallToAction"
    };

    function createPopup(Title: string, Message: string, ModalTypeValue: ModalType_enum, OkButtonTypeValue: OkButtonType_enum) {
        try {
            console.log("Creating popup...")
            const PopupManager_Instance = PopupManager.method<Il2Cpp.Object>("get_Instance").invoke();
            // full class names or just Il2cpp.Class in overload
            const Show_ModalMessageData_method = PopupManager_Instance.method<boolean>("Show", 3).overload(PopupInteractionType, ModalMessageData, "FGClient.UI.UIModalMessage.ModalMessageFailedToShow");
            
            // 1 arg 
            const Info_Value = PopupInteractionType.field<Il2Cpp.ValueType>("Info").value;

            // 2 arg
            const NotLocalised_Value = LocaliseOption.field<Il2Cpp.ValueType>("NotLocalised").value;
            // Create new instance of ModalMessageData class
            // btw, you can't create it in one line, it will return undefined (uhh?)
            const ModalMessageData_Instance = ModalMessageData.alloc();
            ModalMessageData_Instance.method<Il2Cpp.Object>(".ctor").invoke(); 

            ModalMessageData_Instance.field<Il2Cpp.ValueType>("LocaliseTitle").value = NotLocalised_Value; 
            ModalMessageData_Instance.field<Il2Cpp.ValueType>("LocaliseMessage").value = NotLocalised_Value;
            ModalMessageData_Instance.field<Il2Cpp.ValueType>("ModalType").value = ModalType.field<Il2Cpp.ValueType>(ModalTypeValue).value;
            ModalMessageData_Instance.field<Il2Cpp.ValueType>("OkButtonType").value = OkButtonType.field<Il2Cpp.ValueType>(OkButtonTypeValue).value;
            ModalMessageData_Instance.field<Il2Cpp.String>("Title").value = Il2Cpp.string(Title);
            ModalMessageData_Instance.field<Il2Cpp.String>("Message").value = Il2Cpp.string(Message);
            ModalMessageData_Instance.field("OnCloseButtonPressed").value = NULL;
                
            // 3 arg is onFailedCallback delegate, which is default is null
            Show_ModalMessageData_method.invoke(Info_Value, ModalMessageData_Instance, NULL);
        } catch (error: any) {
            Menu.toast(error.stack, 0);
            console.error(error.stack);
        };
    };

    const initMenu = () => {
        try {
            const layout = new Menu.ObsidianLayout(obsidianConfig);
            const composer = new Menu.Composer(en.info.name, en.info.warn, layout); 
            composer.icon(Config.ICON_URL, "Web");

            Menu.add(layout.button("debug", () => {
                    Il2Cpp.perform(() => {
                        createPopup("Test Popup", "Message of Test Popup", ModalType_enum.MT_OK, OkButtonType_enum.Green);
                    }, "main"); // From Java.scheduleOnMainThread you need to Il2cpp.perform main!
                })
            );

            // === Movement Tab === 
            const movement = layout.textView(en.tabs.movement_tab);
            movement.gravity = Menu.Api.CENTER;
            Menu.add(movement);

            Menu.add(
                layout.toggle(en.functions.toggle_360_dives, (state: boolean) => {
                    Config.Toggles.toggle360Dives = state;
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_air_jump, (state: boolean) => {
                    Config.Toggles.toggleAirJump = state;
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_freeze_player, (state: boolean) => {
                    state ? freezePlayer.enable() : freezePlayer.disable();
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_dont_send_fallguy_state, (state: boolean) => {
                    Config.Toggles.toggleDontSendFallGuyState = state;
                })
            );
            
            Menu.add(layout.textView(en.info.fg_state_warn));

            Menu.add(
                layout.toggle(en.functions.toggle_custom_speed, (state: boolean) => {
                    Config.Toggles.toggleCustomSpeed = state;
                })
            );

            Menu.add(
                layout.seekbar(en.functions.custom_speed, 100, 1, (value: number) => {
                    Config.CustomValues.normalMaxSpeed = value;
                })
            ); 

            Menu.add(
                layout.toggle(en.functions.toggle_custom_velocity, (state: boolean) => {
                    Config.Toggles.toggleCustomVelocity = state;
                })
            );

            Menu.add(
                layout.seekbar(en.functions.vertical_gravity_velocity, 100, 0, (value: number) => {
                    Config.CustomValues.maxGravityVelocity = value;
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_negative_velocity, (state: boolean) => {
                    Config.Toggles.toggleNegativeVelocity = state;
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_no_vertical_velocity, (state: boolean) => {
                    Config.Toggles.toggleNoVelocity = state;
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_custom_jump_strength, (state: boolean) => {
                    Config.Toggles.toggleCustomJumpForce = state;
                })
            );

            Menu.add(
                layout.seekbar(en.functions.jump_strength, 100, 1, (value: number) => {
                    Config.CustomValues.jumpForce = value;
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_custom_dive_strength, (state: boolean) => {
                    Config.Toggles.toggleCustomDiveForce = state;
                })
            );

            Menu.add(
                layout.seekbar(en.functions.dive_strength, 100, 1, (value: number) => {
                    Config.CustomValues.diveForce = value;
                })
            );

            // === Round Tab === 
            const round_tab = layout.textView(en.tabs.round_tab);
            round_tab.gravity = Menu.Api.CENTER;
            Menu.add(round_tab);

            Menu.add(
                layout.toggle(en.functions.hide_real_doors, (state: boolean) => {
                    Config.Toggles.toggleHideDoors = state;
                })
            );

            Menu.add(layout.button(en.functions.show_tiptoe_path, showTipToePath));

            // === Teleports Tab === 
            const teleports = layout.textView(en.tabs.teleports_tab);
            teleports.gravity = Menu.Api.CENTER;
            Menu.add(teleports);
            
            Menu.add(layout.button(en.functions.teleport_to_finish_or_crown, teleportToFinish));

            Menu.add(layout.button(en.functions.teleport_to_score, teleportToScore));

            // === Utility Tab === 
            const utility = layout.textView(en.tabs.utility_tab);
            utility.gravity = Menu.Api.CENTER;
            Menu.add(utility);

            Menu.add(layout.button(en.functions.toggle_view_names, () => {
                SetShowPlayerNamesByDefault_method.invoke(!showPlayerNames);
            }));

            Menu.add(
                layout.toggle(en.functions.toggle_custom_fov, (state: boolean) => {
                    Config.Toggles.toggleCustomFov = state;
                })
            );

            Menu.add(
                layout.seekbar(en.functions.custom_fov, 180, 1, (value: number) => {
                    if (Config.Toggles.toggleCustomFov) {
                        changeFov(value);
                    };
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_disable_ui, (state: boolean) => {
                    state ? UICanvas_util.disable() : UICanvas_util.enable();
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_fgdebug, (state: boolean) => {
                    state ? FGDebug.enable() : FGDebug.disable();
                })
            );

            Menu.add(
                layout.toggle(en.functions.toggle_disable_analytics, (state: boolean) => {
                    Config.Toggles.toggleDisableAnalytics = state;
                })
            );

            Menu.add(
                layout.toggle(en.functions.show_number_of_queued_players, (state: boolean) => {
                    Config.Toggles.toggleShowQueuedPlayers = state;
                })
            );

            Menu.add(
                layout.seekbar(en.functions.custom_resolution, 100, 1, (value: number) => {
                    Config.CustomValues.ResolutionScale = value / 100;
                    changeResolutionScale(); 
                })
            );

            Menu.add(layout.button(en.functions.show_game_details, showGameDetails));
            Menu.add(layout.button(en.functions.show_and_copy_server_details, showServerDetails));

            // === Links Tab === 
            const links = layout.textView(en.tabs.links_tab);
            links.gravity = Menu.Api.CENTER;
            Menu.add(links);

            Menu.add(layout.button(en.info.github_url, () => openURL(Config.GITHUB_URL)));
            Menu.add(layout.button(en.info.discord_url, () => openURL(Config.DISCORD_URL)));

            // === Build Info Tab ===
            const info = layout.textView(en.tabs.build_info_tab);
            info.gravity = Menu.Api.CENTER;
            Menu.add(info);

            Menu.add(layout.textView(`${en.info.mod_menu_version} ${modPreferences.VERSION}`));
            Menu.add(layout.textView(`${en.info.mod_menu_env} ${modPreferences.ENV}`));
            Menu.add(layout.textView(`${en.info.game_version} ${Config.BuildInfo.gameVersion}`));
            Menu.add(layout.textView(`${en.info.is_spoofed} ${Config.USE_SPOOF}`));
            if (Config.USE_SPOOF)
                Menu.add(layout.textView(`${en.info.spoofed_game_version} ${Config.BuildInfo.spoofedGameVersion}`));
            Menu.add(layout.textView(`${en.info.original_signature} ${Config.BuildInfo.originalSignature}`));
            if (Config.USE_SPOOF)
                Menu.add(layout.textView(`${en.info.spoofed_signature} ${Config.BuildInfo.spoofedSignature}`));
            Menu.add(layout.textView(`${en.info.platform} ${Config.BuildInfo.PLATFORM}`));
            Menu.add(layout.textView(`${en.info.unity_version} ${Config.BuildInfo.unityVersion}`));
            Menu.add(layout.textView(`${en.info.game_build_number} ${Config.BuildInfo.buildNumber}`));
            Menu.add(layout.textView(`${en.info.game_build_date} ${Config.BuildInfo.buildDate}`));
            Menu.add(layout.textView(`${en.info.package_name} ${Il2Cpp.application.identifier}`));

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
            Menu.toast(error.stack, 1);
            console.error(error.stack);
        }
    };
}

Il2Cpp.perform(main);
