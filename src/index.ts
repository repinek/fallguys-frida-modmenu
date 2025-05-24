import "frida-il2cpp-bridge";
import "frida-java-menu";
import { obsidianConfig } from "./menuConfig.js";
import { openURL, copyToClipboard } from "./utils.js";
import { Config } from "./vars.js";

function main() {
    // === Assemblies === 
    const TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image; // FG.Common namespace
    const CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    const MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image; // FGClient namespace
    const WushuLevelEditorRuntime = Il2Cpp.domain.assembly("Wushu.LevelEditor.Runtime").image; // creative logic

    // === Classes === 
    const Resources = CoreModule.class("UnityEngine.Resources");
    const Vector3class = CoreModule.class("UnityEngine.Vector3");
    const SceneManager = CoreModule.class("UnityEngine.SceneManagement.SceneManager");
    const CCamera = CoreModule.class("UnityEngine.Camera"); 

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

    const CharacterDataMonitor = TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
    const FallGuysCharacterController = TheMultiplayerGuys.class("FallGuysCharacterController");
    const MotorFunctionJump = TheMultiplayerGuys.class("FG.Common.Character.MotorFunctionJump");
    const MPGNetMotorTasks = TheMultiplayerGuys.class("FG.Common.MPGNetMotorTasks"); // MPG - The Multiplayer Group 

    const DebugClass = TheMultiplayerGuys.class("GvrFPS"); // FGDebug

    const ObjectiveReachEndZone = TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone"); // finish
    const GrabToQualify = TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify"); // crown
    const SpawnableCollectable = TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"); // bubble unity
    const COMMON_ScoringBubble = TheMultiplayerGuys.class("Levels.Progression.COMMON_ScoringBubble") // bubble creative
    const ScoredButton = TheMultiplayerGuys.class("ScoredButton"); // trigger button unity
    const TipToe_Platform = TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");
    const FakeDoorController = TheMultiplayerGuys.class("Levels.DoorDash.FakeDoorController");
    const CrownMazeDoor = TheMultiplayerGuys.class("Levels.CrownMaze.CrownMazeDoor");
    const FollowTheLeaderZone = TheMultiplayerGuys.class("Levels.ScoreZone.FollowTheLeader.FollowTheLeaderZone"); // leading light
    const LevelEditorTriggerZoneActiveBase = WushuLevelEditorRuntime.class("LevelEditorTriggerZoneActiveBase"); // trigger zone creative

    // === Methods === 
    const set_fieldOfView_method = CCamera.method("set_fieldOfView", 1);
    const BuildInfo_OnEnable_method = BuildInfo.method("OnEnable");
    const get_TargetFrameRate_method = GraphicsSettings.method("get_TargetFrameRate");
    const set_TargetFrameRate_method = GraphicsSettings.method("set_TargetFrameRate", 1);
    const get_ResolutionScale_method = GraphicsSettings.method("get_ResolutionScale");
    const set_ResolutionScale_method = GraphicsSettings.method("set_ResolutionScale", 1);
    const SetShowPlayerNamesByDefault_method = PlayerInfoHUDBase.method("SetShowPlayerNamesByDefault", 1);
        
    const CheckAntiCheatClientServiceForError_method = MainMenuViewModel.method<boolean>("CheckAntiCheatClientServiceForError"); 
    const ShowAntiCheatPopup_method = MainMenuViewModel.method("ShowAntiCheatPopup", 2);

    const GameLevelLoaded_method = ClientGameManager.method("GameLevelLoaded", 1);

    const OnMainMenuDisplayed_method = LobbyService.method("OnMainMenuDisplayed", 1);
    const StartAFKManager_method = AFKManager.method("Start");
    const ProcessMessageReceived_method = FNMMSClientRemoteService.method("ProcessMessageReceived");

    const CheckCharacterControllerData_method = CharacterDataMonitor.method("CheckCharacterControllerData", 1); 
    const CanJump_method = MotorFunctionJump.method<boolean>("CanJump");
    const SendMessage_method = MPGNetMotorTasks.method("SendMessage", 1);

    console.log("Loaded il2cpp, assemblies, classes and method pointers")

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

    let reachedMainMenu = false;
    let current_SceneName;
    let showPlayerNames_state: boolean;
    let lastTeleportTime = 0;
    const TELEPORT_COOLDOWN = 1000; // teleport cooldown for Teleports
    
    Menu.toast("Menu will appear once you enter the main menu", 1);

    // === Hooks ===

    // Bypass permanent ban
    // you can't bypass a temporary ban, but you can bypass a permanent one, lmao
    CheckAntiCheatClientServiceForError_method.implementation = function () {
        console.log("CheckAntiCheatClientServiceForError Called!"); 
        return false; // idk how it works, but it works (you can't enter the match without this hook)
    };
    
    ShowAntiCheatPopup_method.implementation = function (errorMessage, shouldQuit) { // AntiCheatError errorMessage, bool shouldQuit
        console.log("ShowAntiCheatPopup Called with args:", errorMessage, shouldQuit); 
        // Called by: bool FGClient::MainMenuViewModel::_CheckRestrictedGameAccess_d__69::MoveNext

        //@ts-ignore
        const AntiCheatErrorMessageString = errorMessage.method("get_Message").invoke().content;
        if (AntiCheatErrorMessageString === "restrict_game_access" && shouldQuit === true) {
            console.log("Detected permanent ban");
            /* 
            You can probably can hook FGClient::UI::PopupManager::Show
            and get cool Popup if you change something in ModalMessageData data argument
            */
            Menu.toast("Your account has permanent ban, but you can still play with mod menu. Enjoy", 1); 
        };

        return; 
    };

    // Graphics 
    set_fieldOfView_method.implementation = function (value) {
        Camera_Instance = this;
        if (Config.Toggles.enableCustomFOV) {
            value = Config.CustomValues.FOV;
        } 
        return this.method("set_fieldOfView", 1).invoke(value);
    };

    get_TargetFrameRate_method.implementation = function () {
        console.log("get_TargetFrameRate Called!");
        return 1488; // fps limit
    };

    set_TargetFrameRate_method.implementation = function (fps) {
        console.log("set_TargetFrameRate Called!");
        return this.method("set_TargetFrameRate", 1).invoke(1488); // fps limit
    };

    get_ResolutionScale_method.implementation = function () {
        console.log("get_ResolutionScale Called!");
        GraphicsSettings_Instance = this; // often gc.choose causes crashes

        if (!reachedMainMenu) {
            return this.method("get_ResolutionScale").invoke(); // return value from game config, if the menu is not loaded
        }

        return Config.CustomValues.ResolutionScale;
    };

    set_ResolutionScale_method.implementation = function (scale) {
        console.log("set_ResolutionScale called!")

        if (!reachedMainMenu) {
            return this.method("set_ResolutionScale", 1).invoke(scale); // return value from game config, if the menu is not loaded
        }

        return this.method("set_ResolutionScale", 1).invoke(Config.CustomValues.ResolutionScale); 
    };

    SetShowPlayerNamesByDefault_method.implementation = function (value) {
        console.log("SetShowPlayerNamesByDefault Called!");
        //@ts-ignore idk i can't set value: boolean
        showPlayerNames_state = value;
        return this.method("SetShowPlayerNamesByDefault", 1).invoke(value);
    };

    // Some Utils 
    StartAFKManager_method.implementation = function () {
        console.log("AFKManager Start Called!");
        return; // anti-afk implementation 
    };

    OnMainMenuDisplayed_method.implementation = function (event) {
        console.log("OnMainMenuDisplayed Called!");

        if (!reachedMainMenu) {
            Menu.toast("Showing menu", 0);
            /*
            sooo, if you load all these assemblies before the menu appears, the game will freeze when entering the main menu. 
            probably, the shitcode from the menu is affecting this, idk.

            you can load the menu here, in this function, and it will wait another 2 seconds in the initMenu function before showing it (bad, but working (not always)), 
            */
            Menu.waitForInit(initMenu);
            reachedMainMenu = true;
            if (Config.Toggles.enableFGDebug) {
                FGDebug.enable();
            }
        }

        return this.method("OnMainMenuDisplayed", 1).invoke(event);
    };

    GameLevelLoaded_method.implementation = function (ugcLevelHash) {
        console.log("GameLevelLoaded called!");

        ClientGameManager_Instance = this;

        GlobalGameStateClient_Instance = GlobalGameStateClient.method<Il2Cpp.Object>("get_Instance").invoke();

        const Scene_Instance = SceneManager.method<Il2Cpp.Object>("GetActiveScene").invoke();
        current_SceneName = Scene_Instance.method<Il2Cpp.String>("get_name").invoke().content; // it's better to check by SceneName, instead round id (and easier lol)
        console.log(current_SceneName);

        if (Config.Toggles.enableHideDoors) {
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
            case current_SceneName?.includes("FallGuy_DoorDash"):
                manipulateObjects(FakeDoorController, "get_IsFakeDoor", false);
                break;
        
            case current_SceneName?.includes("FallGuy_Crown_Maze_Topdown"):
                manipulateObjects(CrownMazeDoor, "get_IsBreakable", true);
                break;
        
            case current_SceneName?.includes("Fraggle"): // creative codename
                manipulateObjects(FakeDoorController, "get_IsFakeDoor", false);
                break;
            }
        }

        return this.method("GameLevelLoaded", 1).invoke(ugcLevelHash);
    };

    SendMessage_method.implementation = function (bypassNetworkLOD) {
        if (Config.Toggles.enableDontSendFallGuyState) {
            return false;
        }
        return this.method("SendMessage", 1).invoke(bypassNetworkLOD);
    };

    //@ts-ignore, code from wiki snippets btw lol
    ProcessMessageReceived_method.implementation = function (jsonMessage: Il2Cpp.String) {
        console.log("ProcessMessageReceived called!");

        if (Config.Toggles.enableShowQueuedPlayers) {
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
        Config.BuildInfo.appVersion = Il2Cpp.application.version!;
        Config.BuildInfo.unityVersion = Il2Cpp.unityVersion;
        Config.BuildInfo.buildNumber = this.field<Il2Cpp.String>("buildNumber").value.content!;
        Config.BuildInfo.commit = this.field<Il2Cpp.String>("commit").value.content!;
        Config.BuildInfo.buildDate = this.field<Il2Cpp.String>("buildDate").value.content!;
        Config.BuildInfo.EOSVersion = this.field<Il2Cpp.String>("eosVersion").value.content!;
        // you can also get pewVersion and kittVersion here if you want. also _fullString and _shortString

        return this.method("OnEnable").invoke();
    };

    // Physics 
    CheckCharacterControllerData_method.implementation = function (character: any) {
    
        FallGuysCharacterController_Instance = character;
        CharacterControllerData_Instance = character.method("get_Data").invoke(); // get Data instance
        JumpMotorFunction_Instance = character.method("get_JumpMotorFunction").invoke(); // get JumpMotorFunction 
    
        CharacterControllerData_Instance.field("divePlayerSensitivity").value = Config.Toggles.enable360Dives ? 14888 : Config.DefaultValues.divePlayerSensitivity;

        CharacterControllerData_Instance.field("normalMaxSpeed").value = Config.Toggles.enableCustomSpeed ? Config.CustomValues.normalMaxSpeed : Config.DefaultValues.normalMaxSpeed;
        CharacterControllerData_Instance.field("carryMaxSpeed").value = Config.Toggles.enableCustomSpeed ? Config.CustomValues.normalMaxSpeed : Config.DefaultValues.carryMaxSpeed;
        CharacterControllerData_Instance.field("grabbingMaxSpeed").value = Config.Toggles.enableCustomSpeed ? Config.CustomValues.normalMaxSpeed : Config.DefaultValues.grabbingMaxSpeed;

        CharacterControllerData_Instance.field("maxGravityVelocity").value = Config.Toggles.enableCustomVelocity
            ? Config.Toggles.enableNoVelocity 
                ? 0 // if enable no velocity
                : Config.Toggles.enableNegativeVelocity
                  ? -Config.CustomValues.maxGravityVelocity // if enable negative velocity
                  : Config.CustomValues.maxGravityVelocity
            : Config.DefaultValues.maxGravityVelocity;
        
        CharacterControllerData_Instance.field("diveForce").value = Config.Toggles.enableCustomDiveForce ? Config.CustomValues.diveForce : Config.DefaultValues.diveForce;
        CharacterControllerData_Instance.field("airDiveForce").value = Config.Toggles.enableCustomDiveForce ? Config.CustomValues.diveForce : Config.DefaultValues.airDiveForce;

        const jumpForce = JumpMotorFunction_Instance.field<Il2Cpp.Object>("_jumpForce").value;
        jumpForce.field("y").value = Config.Toggles.enableCustomJumpForce ? Config.CustomValues.jumpForce : Config.DefaultValues.jumpForce;
    
        return true;
    };

    CanJump_method.implementation = function () {
        if (Config.Toggles.enableAirJump) {
            return true;
        }
        return this.method<boolean>("CanJump").invoke();
    };

    // === Helpers === 
    const findObjectsOfTypeAll = (klass: Il2Cpp.Class) => {
    return Resources.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1).invoke(klass.type.object);
    };

    const teleportTo = (target: Il2Cpp.Object) => {
    const ObjectVector3Pos = target
        .method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method<Il2Cpp.Object>("get_position")
        .invoke();

    FallGuysCharacterController_Instance
        .method<Il2Cpp.Object>("get_transform")
        .invoke()
        .method<Il2Cpp.Object>("set_position")
        .invoke(ObjectVector3Pos);
    };

    // === Functions === 
    const FGDebug = {
        enable() {
            Config.Toggles.enableFGDebug = true;

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
            Config.Toggles.enableFGDebug = false;
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

    const teleportToFinish = () => {
        // Check if enough time has passed since thelast teleport
        const currentTime = Date.now();
        if (currentTime - lastTeleportTime < TELEPORT_COOLDOWN) {
            Menu.toast(`Please wait ${((TELEPORT_COOLDOWN - (currentTime - lastTeleportTime)) / 1000).toFixed(1)} seconds before teleporting again!`, 0);
            return;
        }
        lastTeleportTime = currentTime;
        
        let EndZoneObject: Il2Cpp.Object | null;
        let CrownObject: Il2Cpp.Object | null;
    
        const EndZoneArray = findObjectsOfTypeAll(ObjectiveReachEndZone);
        if (EndZoneArray.length > 0) {
            EndZoneObject = EndZoneArray.get(0);
        }
    
        const CrownArray = findObjectsOfTypeAll(GrabToQualify);
        if (CrownArray.length > 0) {
            CrownObject = CrownArray.get(0);
        }
    
        const FinishObject = EndZoneObject! ?? CrownObject!;
        if (FinishObject) {
            teleportTo(FinishObject);
        } else {
            Menu.toast(`No Finish or Crown was found. The round probably does not have a finish or a crown.`, 0);
        }
    };
    
    const teleportToScorePoint = () => {
        // Check if enough time has passed since last teleport
        const currentTime = Date.now();
        if (currentTime - lastTeleportTime < TELEPORT_COOLDOWN) {
            Menu.toast(`Please wait ${((TELEPORT_COOLDOWN - (currentTime - lastTeleportTime)) / 1000).toFixed(1)} seconds before teleporting again!`, 0);
            return;
        }
        lastTeleportTime = currentTime;
        
        try {
            const UnityBubblesArray = findObjectsOfTypeAll(SpawnableCollectable); // unity bubbles
            const CreativeBubblesArray = findObjectsOfTypeAll(COMMON_ScoringBubble); // creative bubbles
            const ScoredButtonArray = findObjectsOfTypeAll(ScoredButton);
            const creativeScoreZonesArray = findObjectsOfTypeAll(LevelEditorTriggerZoneActiveBase); // creative scorezones
            const FollowTheLeaderZonesArray = findObjectsOfTypeAll(FollowTheLeaderZone) // leading light 
    
            // Rest of the function remains the same...
            for (const bubble of UnityBubblesArray) {
                if (bubble.method<boolean>("get_Spawned").invoke()) {
                    teleportTo(bubble);
                    return;
                }
            }
    
            for (const bubble of CreativeBubblesArray) {
                if (bubble.field<number>("_pointsAwarded").value > 0) {
                    let bubbleHandle = bubble.field<Il2Cpp.Object>("_bubbleHandle").value;
                    if (bubbleHandle.field<boolean>("_spawned").value) {
                        teleportTo(bubble);
                        return;
                    }
                }
            }
    
            for (const button of ScoredButtonArray) {
                if (button.field<boolean>("_isAnActiveTarget").value) {
                    teleportTo(button);
                    return;
                }
            }
    
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
    
        } catch (error: any) {
            console.error(error.stack);
            Menu.toast(error.stack, 0);
        }
        Menu.toast("No bubbles or buttons were found. Please open an issue if it does not work.", 0);
    };
    
    const teleportToRandomPlayer = () => {
        // Check if enough time has passed since the last teleport
        const currentTime = Date.now();
        if (currentTime - lastTeleportTime < TELEPORT_COOLDOWN) {
            Menu.toast(`Please wait ${((TELEPORT_COOLDOWN - (currentTime - lastTeleportTime)) / 1000).toFixed(1)} seconds before teleporting again!`, 0);
            return;
        }
        lastTeleportTime = currentTime;
        
        const FallGuysCharacterControllerArray = findObjectsOfTypeAll(FallGuysCharacterController); 
        
        if (FallGuysCharacterControllerArray.length === 1) {
            Menu.toast(`You can't teleport to yourself.`, 0);
            return;
        }
        else if (FallGuysCharacterControllerArray.length > 0) {
            const RandomIndex = Math.floor(Math.random() * FallGuysCharacterControllerArray.length); // random
            const RandomPlayer = FallGuysCharacterControllerArray.get(RandomIndex);

            teleportTo(RandomPlayer);
            return;
        } else {
            Menu.toast(`No Players were found!`, 0);
            return;
        };
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
            console.log("trying change resolution scale to", Config.CustomValues.ResolutionScale);
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
                const NetworkManager = GlobalGameStateClient_Instance.method<Il2Cpp.Object>("get_NetworkManager").invoke();
                const GameConnection = NetworkManager.method<Il2Cpp.Object>("get_ConnectionToServer").invoke();

                const HostIPAddr = NetworkManager.method<Il2Cpp.String>("get_HostIPAddr").invoke().content;
                const HostPortNo = NetworkManager.method<number>("get_HostPortNo").invoke();
                const RTT = GameConnection.method<number>("CurrentRtt").invoke(); 
                const LAG = GameConnection.method<number>("CurrentLag").invoke();

                console.log(`Server: ${HostIPAddr}:${HostPortNo}\nPing: ${RTT}ms, LAG: ${LAG} `);
                Menu.toast(`Server: ${HostIPAddr}:${HostPortNo}. Ping: ${RTT}ms, LAG: ${LAG}`, 0); // little secret, you can ddos these servers, and its not too hard.
                copyToClipboard(`${HostIPAddr}:${HostPortNo}`);
            } else {
                Menu.toast("You are not in the game!", 0);
            }
        } catch (error: any) {
            Menu.toast("You are not in the game!", 0);
            console.error(error.stack);
        }
    };

    // WIP
    const showGameDetails = () => {
        try {
            if (ClientGameManager_Instance) {
                const round = ClientGameManager_Instance.field<Il2Cpp.Object>("_round").value;
                const roundID = round.method<Il2Cpp.String>("get_Id").invoke().content;
                const Seed = ClientGameManager_Instance.method<number>("get_RandomSeed").invoke();
                const initialNumParticipants = ClientGameManager_Instance.field<number>("_initialNumParticipants").value;
                // const AllPlayers = ClientGameManager_Instance.method<Il2Cpp.Array<Il2Cpp.Object>>("get_AllPlayers").invoke();
                const EliminatedPlayerCount = ClientGameManager_Instance.field<number>("_eliminatedPlayerCount").value;

                // console.log(AllPlayers, typeof(AllPlayers), AllPlayers.length); // System.Collections.Generic.List`1[FGClient.NetworkPlayerDataClient] object undefined

                /*
                console.log(`RoundID: ${roundID}, Seed: ${Seed}, Initial Players: ${initialNumParticipants}, Remain Players: ${(AllPlayers.length - EliminatedPlayerCount)}, 
                Eliminated Players: ${EliminatedPlayerCount}`);
                Menu.toast(`RoundID: ${roundID}, Seed: ${Seed}, Initial Players: ${initialNumParticipants}, Remain Players: ${(AllPlayers.length - EliminatedPlayerCount)}, 
                Eliminated Players: ${EliminatedPlayerCount}`, 0);
                */ 

                console.log(`RoundID: ${roundID}, Seed: ${Seed}, Initial Players: ${initialNumParticipants}, 
                Eliminated Players: ${EliminatedPlayerCount}`);
                
                Menu.toast(`RoundID: ${roundID}, Seed: ${Seed}, Initial Players: ${initialNumParticipants}, 
                Eliminated Players: ${EliminatedPlayerCount}`, 0);

            } else {
                Menu.toast("You are not in the game!", 0);
            }
        } catch (error: any) {
            Menu.toast("You are not in the game!", 0);
            console.error(error.stack);
        }
    };

    // test
    const showTipToePath = () => {
        try {
            const TipToe_PlatformArray = findObjectsOfTypeAll(TipToe_Platform);

            console.log("TipToePlatforms found: ", TipToe_PlatformArray.length);
            Menu.toast("TipToePlatforms found: ", TipToe_PlatformArray.length);
    
            for (const TipToe of TipToe_PlatformArray) {
                const TipToeStatus = TipToe.method<boolean>("get_IsFakePlatform").invoke();
                if (TipToeStatus) { // if fake
                    console.log("Found FakePlatform, deactivating...")
                    const TipToeObject = TipToe.method<Il2Cpp.Object>("get_gameObject").invoke();
                    TipToeObject.method("SetActive").invoke(false);
                }
            }
        } catch (error: any) {
            Menu.toast(error.stack, 0);
            console.error(error.stack);
        }
    };


    const initMenu = () => {
        try {
            const layout = new Menu.ObsidianLayout(obsidianConfig);
            const composer = new Menu.Composer("Fall Guys Mod Menu", "IF YOU BOUGHT IT YOU WERE SCAMMED", layout);
            composer.icon("https://floyzi.github.io/images/obed-guys-present.png", "Web");

            // === Movement Tab === 
            const movement = layout.textView("<b>--- Movement ---</b>");
            movement.gravity = Menu.Api.CENTER;
            Menu.add(movement);

            Menu.add(
                layout.toggle("360 Dives", (state: boolean) => {
                    Config.Toggles.enable360Dives = state;
                    console.log(`enable360Dives: ${Config.Toggles.enable360Dives}`);
                })
            );

            Menu.add(
                layout.toggle("Air Jump", (state: boolean) => {
                    Config.Toggles.enableAirJump = state;
                    console.log(`enableAirJump: ${Config.Toggles.enableAirJump}`);
                })
            );

            Menu.add(
                layout.toggle("Freeze Player", (state: boolean) => {
                    state ? freezePlayer.enable() : freezePlayer.disable();
                })
            );

            Menu.add(
                layout.toggle("Don't send Fall Guy state", (state: boolean) => {
                    Config.Toggles.enableDontSendFallGuyState = state;
                    console.log(`enableDontSendFallGuyState: ${Config.Toggles.enableDontSendFallGuyState}`);
                })
            );

            Menu.add(
                layout.toggle("Enable Custom Speed", (state: boolean) => {
                    Config.Toggles.enableCustomSpeed = state;
                    console.log(`enableCustomSpeed: ${Config.Toggles.enableCustomSpeed}`);
                })
            );

            Menu.add(
                layout.seekbar("Custom Speed: {0} / 100", 100, 1, (value: number) => {
                    Config.CustomValues.normalMaxSpeed = value;
                    console.log(`normalMaxSpeed: ${Config.CustomValues.normalMaxSpeed}`);
                })
            ); 

            Menu.add(
                layout.toggle("Enable Custom Velocity", (state: boolean) => {
                    Config.Toggles.enableCustomVelocity = state;
                    console.log(`enableCustomVelocity: ${Config.Toggles.enableCustomVelocity}`);
                })
            );

            Menu.add(
                layout.seekbar("Vertical Gravity Velocity: {0} / 100", 100, 0, (value: number) => {
                    Config.CustomValues.maxGravityVelocity = value;
                    console.log(`maxGravityVelocity: ${Config.CustomValues.maxGravityVelocity}`);
                })
            );

            Menu.add(
                layout.toggle("Negative Velocity", (state: boolean) => {
                    Config.Toggles.enableNegativeVelocity = state;
                    console.log(`enableNegativeVelocity: ${Config.Toggles.enableNegativeVelocity}`);
                })
            );

            Menu.add(
                layout.toggle("No Vertical Velocity", (state: boolean) => {
                    Config.Toggles.enableNoVelocity = state;
                    console.log(`enableNoVelocity: ${Config.Toggles.enableNoVelocity}`);
                })
            );

            Menu.add(
                layout.toggle("Enable Custom Jump Strength", (state: boolean) => {
                    Config.Toggles.enableCustomJumpForce = state;
                    console.log(`enableCustomJumpForce: ${Config.Toggles.enableCustomJumpForce}`);
                })
            );

            Menu.add(
                layout.seekbar("Jump Strength: {0} / 100", 100, 1, (value: number) => {
                    Config.CustomValues.jumpForce = value;
                    console.log(`jumpForce: ${Config.CustomValues.jumpForce}`);
                })
            );

            Menu.add(
                layout.toggle("Enable Custom Dive Strength", (state: boolean) => {
                    Config.Toggles.enableCustomDiveForce = state;
                    console.log(`enableCustomDiveForce: ${Config.Toggles.enableCustomDiveForce}`);
                })
            );

            Menu.add(
                layout.seekbar("Dive Strength: {0} / 100", 100, 1, (value: number) => {
                    Config.CustomValues.diveForce = value;
                    console.log(`diveForce: ${Config.CustomValues.diveForce}`);
                })
            );

            // === Round Tab === 
            const round = layout.textView("<b>--- Round ---</b>");
            round.gravity = Menu.Api.CENTER;
            Menu.add(round);

            Menu.add(
                layout.toggle("Hide Real Doors", (state: boolean) => {
                    Config.Toggles.enableHideDoors = state;
                    console.log(`enableHideDoors: ${Config.Toggles.enableHideDoors}`);
                })
            );

            Menu.add(layout.button("Show TipToe Path", showTipToePath));

            // === Teleports Tab === 
            const teleports = layout.textView("<b>--- Teleports ---</b>");
            teleports.gravity = Menu.Api.CENTER;
            Menu.add(teleports);
            
            Menu.add(layout.button("Teleport To Finish or Crown", teleportToFinish));

            Menu.add(layout.button("Teleport To Random Player", teleportToRandomPlayer));

            Menu.add(layout.button("Teleport To Bubble, Active Button, or Score Zone", teleportToScorePoint));

            // === Utility Tab === 
            const utility = layout.textView("<b>--- Utility ---</b>");
            utility.gravity = Menu.Api.CENTER;
            Menu.add(utility);

            Menu.add(layout.button("Toggle View Names", () => {
                SetShowPlayerNamesByDefault_method.invoke(!showPlayerNames_state);
            }));

            Menu.add(
                layout.toggle("Enable Custom FOV", (state: boolean) => {
                    Config.Toggles.enableCustomFOV = state;
                    console.log(`enableCustomFOV: ${Config.Toggles.enableCustomFOV}`);
                })
            );

            Menu.add(
                layout.seekbar("Custom FOV: {0}", 180, 1, (value: number) => {
                    if (Config.Toggles.enableCustomFOV) {
                        if (Camera_Instance) {
                            Config.CustomValues.FOV = value;
                            Camera_Instance.method("set_fieldOfView", 1).invoke(value);
                            console.log(`customFOV: ${Config.CustomValues.FOV}`);
                        };
                    };
                })
            );

            Menu.add(
                layout.toggle("Disable UI (controls won't be work)", (state: boolean) => {
                    state ? UICanvas_util.disable() : UICanvas_util.enable();
                })
            );

            Menu.add(
                layout.toggle("Display FGDebug", (state: boolean) => {
                    state ? FGDebug.enable() : FGDebug.disable();
                })
            );

            Menu.add(
                layout.toggle("Show Number of Queued Players", (state: boolean) => {
                    Config.Toggles.enableShowQueuedPlayers = state;
                    console.log(`enableQueuedPlayers: ${Config.Toggles.enableShowQueuedPlayers}`);
                })
            );

            Menu.add(
                layout.seekbar("Custom Resolution (Applied in Next Round): {0}% / 100%", 100, 1, (value: number) => {
                    Config.CustomValues.ResolutionScale = value / 100;
                    changeResolutionScale(); 
                    console.log(`customResolutionScale: ${Config.CustomValues.ResolutionScale}`);
                })
            );

            Menu.add(layout.button("Show Game Details", showGameDetails));
            Menu.add(layout.button("Show and Copy Server Details", showServerDetails));

            // === Links Tab === 
            const links = layout.textView("<b>--- Links ---</b>");
            links.gravity = Menu.Api.CENTER;
            Menu.add(links);

            Menu.add(layout.button("Github Repository (Leave a star!)", () => openURL("https://github.com/repinek/fallguys-frida-modmenu")));
            Menu.add(layout.button("Cheating Discord Server", () => openURL("https://discord.gg/cNFJ73P6p3")));
            Menu.add(layout.button("Creator's Twitter", () => openURL("https://x.com/repinek840")));

            // === Build Info Tab ===
            const info = layout.textView("<b>--- Build Info ---</b>");
            info.gravity = Menu.Api.CENTER;
            Menu.add(info);
            
            Menu.add(layout.textView(`Version Mod Menu: ${Config.version}`));
            Menu.add(layout.textView(`Game Version: ${Config.BuildInfo.appVersion}`));
            Menu.add(layout.textView(`Unity Version: ${Config.BuildInfo.unityVersion}`))
            Menu.add(layout.textView(`Game Build Number: ${Config.BuildInfo.buildNumber}`));
            Menu.add(layout.textView(`Game Commit: ${Config.BuildInfo.commit}`));
            Menu.add(layout.textView(`Game build Date: ${Config.BuildInfo.buildDate}`));
            Menu.add(layout.textView(`EOS SDK: ${Config.BuildInfo.EOSVersion}`));
            Menu.add(layout.textView(`Package Name: ${Il2Cpp.application.identifier}`));

            const author = layout.textView("Created by repinek");
            author.gravity = Menu.Api.CENTER;
            Menu.add(author);
            
            const secondAuthor = layout.textView("Special Thanks to Floyzi102");
            secondAuthor.gravity = Menu.Api.CENTER;
            Menu.add(secondAuthor);

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
