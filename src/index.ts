import "frida-il2cpp-bridge";
import "frida-java-menu";
import { obsidianConfig } from "./menuConfig.js";

// helper functions
function openURL(link: string) {
    Java.perform(() => {
        try {
            console.log(`Opening URL: ${link}`);
            const uri = Java.use("android.net.Uri").parse(link);
            const intent = Java.use("android.content.Intent");
            const activity = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();

            const openIntent = intent.$new("android.intent.action.VIEW", uri);
            openIntent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
            activity.startActivity(openIntent);
        } catch (error: any) {
            Menu.toast(`Failed to open URL: ${error.message}`, 1);
        }
    });
}

function copyToClipboard(text: string) {
    Java.perform(() => {
        try {
            const context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            const clipboardManager = Java.cast(
                context.getSystemService("clipboard"),
                Java.use("android.content.ClipboardManager")
            );
            const javaString = Java.use("java.lang.String");
            const clipData = Java.use("android.content.ClipData")
                .newPlainText(javaString.$new("label"), javaString.$new(text));
            clipboardManager.setPrimaryClip(clipData);
        } catch (error: any) {
            console.error(`Failed to copy to clipboard: ${error.message}`);
        }
    });
}


// TODO: 
// get_ResolutionScale saving // invoke SetSettingPrefIfChanged(keypref, value), but idk why i cant, enums broken or smth
// checkpoints teleports for lap // hard to implement
// fix follow the leader teleport (add +y)
// remainplayers in show game details
const version = "1.94";

// enablers
let enable360Dives: boolean;
let enableAirJump: boolean;
let enableCustomSpeed: boolean;
let enableCustomVelocity: boolean;
let enableNegativeVelocity: boolean;
let enableNoVelocity: boolean;
let enableCustomJump: boolean;
let enableCustomDiveForce: boolean;
let enableCustomFOV: boolean;
let enableFGDebug: boolean;
let enableHideStuff: boolean;
let enableQueuedPlayers: boolean;

// numbers
let customNormalMaxSpeed = 9.5;
let customMaxGravityVelocity = 40;
let customJumpForceUltimateParty = 17.5;
let customDiveForce = 16.5;
let customResolutionScale = 1;
let customFOV = 68;

function main() {
    // assemblies 
    const TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image; // FG.Common namespace
    const CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    const MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image; // FGClient namespace
    const WushuLevelEditorRuntime = Il2Cpp.domain.assembly("Wushu.LevelEditor.Runtime").image; // creative logic

    // classes
    const Resources = CoreModule.class("UnityEngine.Resources");
    const Vector3class = CoreModule.class("UnityEngine.Vector3");
    const SceneManager = CoreModule.class("UnityEngine.SceneManagement.SceneManager");
    const CCamera = CoreModule.class("UnityEngine.Camera"); 

    const GraphicsSettings = MTFGClient.class("FGClient.GraphicsSettings");
    const LobbyService = MTFGClient.class("FGClient.CatapultServices.LobbyService");
    const GlobalGameStateClient = MTFGClient.class("FGClient.GlobalGameStateClient");
    const ClientGameManager = MTFGClient.class("FGClient.ClientGameManager");
    const AFKManager = MTFGClient.class("FGClient.AFKManager");
    const FNMMSClientRemoteService = MTFGClient.class("FGClient.FNMMSClientRemoteService");
    const UICanvas = MTFGClient.class("FGClient.UI.Core.UICanvas");

    const CharacterDataMonitor = TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
    const FallGuysCharacterController = TheMultiplayerGuys.class("FallGuysCharacterController");
    const MotorFunctionJump = TheMultiplayerGuys.class("FG.Common.Character.MotorFunctionJump");

    const DebugClass = TheMultiplayerGuys.class("GvrFPS"); // debug info

    const ObjectiveReachEndZone = TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone"); // finish
    const GrabToQualify = TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify"); // crown
    const SpawnableCollectable = TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"); // unity level bubble
    const COMMON_ScoringBubble = TheMultiplayerGuys.class("Levels.Progression.COMMON_ScoringBubble") // creative bubble
    const ScoredButton = TheMultiplayerGuys.class("ScoredButton");
    const TipToe_Platform = TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");
    const FakeDoorController = TheMultiplayerGuys.class("Levels.DoorDash.FakeDoorController");
    const CrownMazeDoor = TheMultiplayerGuys.class("Levels.CrownMaze.CrownMazeDoor");
    const FollowTheLeaderZone = TheMultiplayerGuys.class("Levels.ScoreZone.FollowTheLeader.FollowTheLeaderZone"); // leading light
    const LevelEditorTriggerZoneActiveBase = WushuLevelEditorRuntime.class("LevelEditorTriggerZoneActiveBase");

    // methods
    const set_fieldOfView_method = CCamera.method("set_fieldOfView", 1);
    
    const get_TargetFrameRate_method = GraphicsSettings.method("get_TargetFrameRate");
    const set_TargetFrameRate_method = GraphicsSettings.method("set_TargetFrameRate", 1);
    const get_ResolutionScale_method = GraphicsSettings.method("get_ResolutionScale");
    const set_ResolutionScale_method = GraphicsSettings.method("set_ResolutionScale", 1);
    const OnMainMenuDisplayed_method = LobbyService.method("OnMainMenuDisplayed", 1);
    const ProcessMessageReceived_method = FNMMSClientRemoteService.method("ProcessMessageReceived");

    const GameLevelLoaded_method = ClientGameManager.method("GameLevelLoaded", 1);
    const CheckCharacterControllerData_method = CharacterDataMonitor.method("CheckCharacterControllerData", 1); 
    const CanJump_method = MotorFunctionJump.method<boolean>("CanJump");
    const StartAFKManager_method = AFKManager.method("Start");

    console.log("Loaded il2cpp, classes and method pointers")

    // storage cache
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
    let lastTeleportTime = 0;
    const TELEPORT_COOLDOWN = 1000; // teleport cooldown for Teleports
    
    Menu.toast("Menu will appear once you enter the main menu", 1);

    // hooks

    // graphics
    get_TargetFrameRate_method.implementation = function () {
        console.log("get_TargetFrameRate Called!");
        return 1488; // fps limit
    };

    set_TargetFrameRate_method.implementation = function (fps) {
        console.log("set_TargetFrameRate Called!");
        return this.method("set_TargetFrameRate", 1).invoke(1488);
    };

    get_ResolutionScale_method.implementation = function () {
        console.log("get_ResolutionScale Called!");
        GraphicsSettings_Instance = this; // often gc.choose causes crashes

        if (!reachedMainMenu) {
            return this.method("get_ResolutionScale").invoke();
        }

        return customResolutionScale;
    };

    set_ResolutionScale_method.implementation = function (scale) {
        console.log("set_ResolutionScale called!")

        if (!reachedMainMenu) {
            return this.method("set_ResolutionScale", 1).invoke(scale);
        }

        return this.method("set_ResolutionScale", 1).invoke(customResolutionScale);
    };

    set_fieldOfView_method.implementation = function (value) {
        Camera_Instance = this;
        if (enableCustomFOV) {
            value = customFOV;
        } 
        return this.method("set_fieldOfView", 1).invoke(value);
    };
    
    // other stuff
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
            if (enableFGDebug) {
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

        if (enableHideStuff) {
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

    //@ts-ignore, code from wiki snippets btw lol
    ProcessMessageReceived_method.implementation = function (jsonMessage: Il2Cpp.String) {
        console.log("ProcessMessageReceived called!");

        if (enableQueuedPlayers) {
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

    // physics
    CheckCharacterControllerData_method.implementation = function (character: any) {
    
        FallGuysCharacterController_Instance = character;
        CharacterControllerData_Instance = character.method("get_Data").invoke(); // get Data instance
        JumpMotorFunction_Instance = character.method("get_JumpMotorFunction").invoke(); // get JumpMotorFunction 
    
        CharacterControllerData_Instance.field("divePlayerSensitivity").value = enable360Dives ? 14888 : 70;
        CharacterControllerData_Instance.field("normalMaxSpeed").value = enableCustomSpeed ? customNormalMaxSpeed : 9.5;
        CharacterControllerData_Instance.field("carryMaxSpeed").value = enableCustomSpeed ? customNormalMaxSpeed : 8;
        CharacterControllerData_Instance.field("grabbingMaxSpeed").value = enableCustomSpeed ? customNormalMaxSpeed : 5;

        CharacterControllerData_Instance.field("maxGravityVelocity").value = enableCustomVelocity
            ? enableNoVelocity 
                ? 0 // if enable no velocity
                : enableNegativeVelocity
                  ? -customMaxGravityVelocity // if enable negative velocity
                  : customMaxGravityVelocity
            : 40;
        
        CharacterControllerData_Instance.field("diveForce").value = enableCustomDiveForce ? customDiveForce : 17.5;
        CharacterControllerData_Instance.field("airDiveForce").value = enableCustomDiveForce ? customDiveForce : 7;

        const jumpForce = JumpMotorFunction_Instance.field<Il2Cpp.Object>("_jumpForce").value;
        jumpForce.field("y").value = enableCustomJump ? customJumpForceUltimateParty : 17.5;
    
        return true;
    };

    CanJump_method.implementation = function () {
        if (enableAirJump) {
            return true;
        }
        return this.method<boolean>("CanJump").invoke();
    };

    // helper functions 
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

    // functions
    const FGDebug = {
        enable() {
            enableFGDebug = true;

            if (!reachedMainMenu) {
                return; // it will enable after hook
            }

            try {
                FGDebug_Instance = findObjectsOfTypeAll(DebugClass).get(0); // find object with debug class

                const localScale = Vector3class.alloc().unbox();
                localScale.method(".ctor", 3).invoke(0.4, 0.4, 0.4); // new scale

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
            enableFGDebug = false;
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
            const characterRigidBody = FallGuysCharacterController_Instance.method<Il2Cpp.Object>("get_RigidBody").invoke();
            characterRigidBody.method("set_isKinematic").invoke(true);
        },
        disable() {
            const characterRigidBody = FallGuysCharacterController_Instance.method<Il2Cpp.Object>("get_RigidBody").invoke();
            characterRigidBody.method("set_isKinematic").invoke(false);
        }
    };
    
    const changeResolutionScale = () => {
        try {
            console.log("trying change resolution scale to", customResolutionScale);
            GraphicsSettings_Instance.method("set_ResolutionScale", 1).invoke(customResolutionScale);
            /*
            i wanted to make this value changeable in the game, but unfortunately 
            calling ResolutionScaling::UpdateResolutionScaleStatus() doesn't do anything,
            maybe i should call something else, but idk exactly (will check later with IDA)
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

            // movement
            const movement = layout.textView("<b>--- Movement ---</b>");
            movement.gravity = Menu.Api.CENTER;
            Menu.add(movement);

            Menu.add(
                layout.toggle("360 Dives", (state: boolean) => {
                    enable360Dives = state;
                    console.log(`enable360Dives: ${enable360Dives}`);
                })
            );

            Menu.add(
                layout.toggle("Air Jump", (state: boolean) => {
                    enableAirJump = state;
                    console.log(`enableAirJump: ${enableAirJump}`);
                })
            );

            Menu.add(
                layout.toggle("Freeze Player", (state: boolean) => {
                    state ? freezePlayer.enable() : freezePlayer.disable();
                })
            );

            Menu.add(
                layout.toggle("Enable Custom Speed", (state: boolean) => {
                    enableCustomSpeed = state;
                    console.log(`enableCustomSpeed: ${enableCustomSpeed}`);
                })
            );

            Menu.add(
                layout.seekbar("Custom Speed: {0} / 100", 100, 1, (value: number) => {
                    customNormalMaxSpeed = value;
                    console.log(`customNormalMaxSpeed: ${customNormalMaxSpeed}`);
                })
            ); 

            Menu.add(
                layout.toggle("Enable Custom Velocity", (state: boolean) => {
                    enableCustomVelocity = state;
                    console.log(`enableCustomVelocity: ${enableCustomVelocity}`);
                })
            );

            Menu.add(
                layout.seekbar("Vertical Gravity Velocity: {0} / 100", 100, 0, (value: number) => {
                    customMaxGravityVelocity = value;
                    console.log(`customMaxGravityVelocity: ${customMaxGravityVelocity}`);
                })
            );

            Menu.add(
                layout.toggle("Negative Velocity", (state: boolean) => {
                    enableNegativeVelocity = state;
                    console.log(`enableNegativeVelocity: ${enableNegativeVelocity}`);
                })
            );

            Menu.add(
                layout.toggle("No Vertical Velocity", (state: boolean) => {
                    enableNoVelocity = state;
                    console.log(`enableNoVelocity: ${enableNoVelocity}`);
                })
            );

            Menu.add(
                layout.toggle("Enable Custom Jump Strength", (state: boolean) => {
                    enableCustomJump = state;
                    console.log(`enableCustomJump: ${enableCustomJump}`);
                })
            );

            Menu.add(
                layout.seekbar("Jump Strength: {0} / 100", 100, 1, (value: number) => {
                    customJumpForceUltimateParty = value;
                    console.log(`customJumpForceUltimateParty: ${customJumpForceUltimateParty}`);
                })
            );

            Menu.add(
                layout.toggle("Enable Custom Dive Strength", (state: boolean) => {
                    enableCustomDiveForce = state;
                    console.log(`enableDiveForce: ${enableCustomDiveForce}`);
                })
            );

            Menu.add(
                layout.seekbar("Dive Strength: {0} / 100", 100, 1, (value: number) => {
                    customDiveForce = value;
                    console.log(`customDiveForce: ${customDiveForce}`);
                })
            );

            // round
            const round = layout.textView("<b>--- Round ---</b>");
            round.gravity = Menu.Api.CENTER;
            Menu.add(round);

            Menu.add(
                layout.toggle("Hide Real Doors", (state: boolean) => {
                    enableHideStuff = state;
                    console.log(`enableHideStuff: ${enableHideStuff}`);
                })
            );

            Menu.add(layout.button("Show TipToe Path", showTipToePath));

            // teleports
            const teleports = layout.textView("<b>--- Teleports ---</b>");
            teleports.gravity = Menu.Api.CENTER;
            Menu.add(teleports);
            
            Menu.add(layout.button("Teleport To Finish or Crown", teleportToFinish));

            Menu.add(layout.button("Teleport To Random Player", teleportToRandomPlayer));

            Menu.add(layout.button("Teleport To Bubble, Active Button, or Score Zone", teleportToScorePoint));

            // other
            const other = layout.textView("<b>--- Other ---</b>");
            other.gravity = Menu.Api.CENTER;
            Menu.add(other);

            Menu.add(
                layout.toggle("Enable Custom FOV", (state: boolean) => {
                    enableCustomFOV = state;
                    console.log(`enableCustomFOV: ${enableCustomFOV}`);
                })
            );

            Menu.add(
                layout.seekbar("Custom FOV: {0}", 180, 1, (value: number) => {
                    if (enableCustomFOV) {
                        if (Camera_Instance) {
                            customFOV = value;
                            Camera_Instance.method("set_fieldOfView", 1).invoke(value);
                            console.log(`customFOV: ${customFOV}`);
                        };
                    };
                })
            );

            Menu.add(
                layout.toggle("Display UI (controls won't be work)", (state: boolean) => {
                    state ? UICanvas_util.enable() : UICanvas_util.disable();
                })
            );

            Menu.add(
                layout.toggle("Display FGDebug", (state: boolean) => {
                    state ? FGDebug.enable() : FGDebug.disable();
                })
            );

            Menu.add(
                layout.toggle("Show Number of Queued Players", (state: boolean) => {
                    enableQueuedPlayers = state;
                    console.log(`enableQueuedPlayers: ${enableQueuedPlayers}`);
                })
            );

            Menu.add(
                layout.seekbar("Custom Resolution (Applied in Next Round): {0}% / 100%", 100, 1, (value: number) => {
                    customResolutionScale = value / 100;
                    changeResolutionScale(); 
                    console.log(`customResolutionScale: ${customResolutionScale}`);
                })
            );

            Menu.add(layout.button("Show Game Details", showGameDetails));
            Menu.add(layout.button("Show and Copy Server Details", showServerDetails));

            // links
            const links = layout.textView("<b>--- Links ---</b>");
            links.gravity = Menu.Api.CENTER;
            Menu.add(links);

            Menu.add(layout.button("Github Repository (Leave a star!)", () => openURL("https://github.com/repinek/fallguys-frida-modmenu")));
            Menu.add(layout.button("Cheating Discord Server", () => openURL("https://discord.gg/cNFJ73P6p3")));
            Menu.add(layout.button("Creator's Twitter", () => openURL("https://x.com/repinek840")));

            const info = layout.textView("<b>--- Some info ---</b>");
            info.gravity = Menu.Api.CENTER;
            Menu.add(info);
            
            Menu.add(layout.textView(`Version Mod Menu: ${version}`));
            Menu.add(layout.textView(`Game Version: ${Il2Cpp.application.version}`));
            Menu.add(layout.textView(`Package Name: ${Il2Cpp.application.identifier}`));

            const author = layout.textView("Created by repinek");
            author.gravity = Menu.Api.CENTER;
            Menu.add(author);

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
