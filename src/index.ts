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

// enablers
let enable360Dives: boolean;
let enableCustomSpeed: boolean;
let enableCustomVelocity: boolean;
let enableNegativeVelocity: boolean;
let enableNoVelocity: boolean;
let enableCustomJump: boolean;
let enableCustomDiveForce: boolean;
let enableFGDebug: boolean;
let enableHideStuff: boolean;

// numbers
let customNormalMaxSpeed = 9.5;
let customMaxGravityVelocity = 40;
let customJumpForceUltimateParty = 17.5;
let customDiveForce = 16.5;
let customResolutionScale = 1;

function main() {
    const TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image;
    const CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    const MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image;

    // classes
    const Resources = CoreModule.class("UnityEngine.Resources");
    const Vector3class = CoreModule.class("UnityEngine.Vector3");

    const GraphicsSettings = MTFGClient.class("FGClient.GraphicsSettings");
    const LobbyService = MTFGClient.class("FGClient.CatapultServices.LobbyService");
    const ClientGameStateView = MTFGClient.class("FGClient.ClientGameStateView");
    const ClientGameManager = MTFGClient.class("FGClient.ClientGameManager");

    const CharacterDataMonitor = TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
    const FallGuysCharacterController = TheMultiplayerGuys.class("FallGuysCharacterController");

    const DebugClass = TheMultiplayerGuys.class("GvrFPS"); // debug info
    const AFKManager = MTFGClient.class("FGClient.AFKManager");

    const ObjectiveReachEndZone = TheMultiplayerGuys.class("FG.Common.COMMON_ObjectiveReachEndZone"); // finish
    const GrabToQualify = TheMultiplayerGuys.class("FG.Common.COMMON_GrabToQualify"); // crowns
    const SpawnableCollectable = TheMultiplayerGuys.class("Levels.ScoreZone.SpawnableCollectable"); // bubbles
    const ScoredButton = TheMultiplayerGuys.class("ScoredButton");
    const TipToe_Platform = TheMultiplayerGuys.class("Levels.TipToe.TipToe_Platform");
    const FakeDoorController = TheMultiplayerGuys.class("Levels.DoorDash.FakeDoorController");
    const CrownMazeDoor = TheMultiplayerGuys.class("Levels.CrownMaze.CrownMazeDoor");

    // methods
    const OnMainMenuDisplayed_method = LobbyService.method("OnMainMenuDisplayed", 1);
    const CheckCharacterControllerData_method = CharacterDataMonitor.method("CheckCharacterControllerData", 1); 
    const get_TargetFrameRate_method = GraphicsSettings.method("get_TargetFrameRate");
    const set_TargetFrameRate_method = GraphicsSettings.method("set_TargetFrameRate", 1);
    const get_ResolutionScale_method = GraphicsSettings.method("get_ResolutionScale");
    const set_ResolutionScale_method = GraphicsSettings.method("set_ResolutionScale", 1);
    const StartAFKManager_method = AFKManager.method("Start");
    const GameLevelLoaded_method = ClientGameManager.method("GameLevelLoaded", 1); // LMAO i was sooo stupid

    let FallGuysCharacterController_stored: Il2Cpp.Object;
    let CharacterControllerData_stored: Il2Cpp.Object;
    let JumpMotorFunction_stored: Il2Cpp.Object;
    let FGDebugInstance: Il2Cpp.Object;

    console.log("Loaded all stuff")

    // storage cache
    let reachedMainMenu = false;
    let GraphicsSettingsInstance: Il2Cpp.Class | Il2Cpp.ValueType | Il2Cpp.Object; // obtaing in get_ResolutionScale

    Menu.toast("Menu will appear once you enter the main menu.", 1);

    get_TargetFrameRate_method.implementation = function () {
        console.log("get_TargetFrameRate Called!");
        return 1488; // fps limit
    };

    set_TargetFrameRate_method.implementation = function (fps) {
        console.log("set_TargetFrameRate Called!");
        return this.method<void>("set_TargetFrameRate", 1).invoke(1488);
    };

    get_ResolutionScale_method.implementation = function () {
        console.log("get_ResolutionScale Called!");
        GraphicsSettingsInstance = this; // often gc.choose causes crashes
        return customResolutionScale;
    }

    set_ResolutionScale_method.implementation = function (scale) {
        console.log("set_ResolutionScale called!")
        return this.method("set_ResolutionScale", 1).invoke(customResolutionScale);
    }

    StartAFKManager_method.implementation = function () { 
        console.log("AFKManager Start Called!");
        return; // anti-afk implementation
    }

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

        return this.method<void>("OnMainMenuDisplayed", 1).invoke(event);
    };

    GameLevelLoaded_method.implementation = function (ugcLevelHash) {
        console.log("GameLevelLoaded called!");

        // TODO: rewrite with ROUND instance
        Il2Cpp.gc.choose(ClientGameStateView).forEach((instance: Il2Cpp.Object) => { // find ClientGameStateView instance
            const currentGameLevelName = instance.field<Il2Cpp.String>("CurrentGameLevelName").value?.content; 

            if (enableHideStuff) {
                try {
                    const disableFakeObjects = (
                        type: Il2Cpp.Class, // class of object
                        field: string, // getter method name like get_IsFakeDoor 
                        expected: boolean
                    ) => {
                        const objectsArray = findObjectsOfTypeAll(type);
            
                        for (const obj of objectsArray) {
                            // const value = obj.field<boolean>(field).value;
                            const value = obj.method<boolean>(field).invoke();
                            if (value === expected) {
                                const gameObject = obj.method<Il2Cpp.Object>("get_gameObject").invoke();
                                gameObject.method("SetActive").invoke(false);
                            }
                        }
                    };
            
                    if (!currentGameLevelName) {
                        Menu.toast("Something went wrong in determining the round ID", 0);
                        return; // i think it exits the current forEach callback iteration, NOT the whole GameLevelLoaded method hook

                    }

                    // why includes? just search round_door_dash or any other in cms, that's why not the ===
                    if (currentGameLevelName.includes("round_door_dash")) {
                        disableFakeObjects(FakeDoorController, "get_IsFakeDoor", false);
                    }
            
                    else if (currentGameLevelName.includes("round_crown_maze")) {
                        disableFakeObjects(CrownMazeDoor, "get_IsBreakable", true);
                    }
            
                    else if (
                        currentGameLevelName.includes("round_tip_toe") || // round_tip_toe_...
                        currentGameLevelName.includes("round_tiptoe") // round_tiptoefinale_...
                    ) {
                        disableFakeObjects(TipToe_Platform, "get_IsFakePlatform", true);
                    }
            
                    else if (currentGameLevelName.includes("ugc")) { // creative
                        disableFakeObjects(FakeDoorController, "get_IsFakeDoor", false);
                    }
    
                } catch (error: any) {
                    Menu.toast(error.stack, 1); 
                    console.error(error.stack);
                }
            }
        });
        
        return this.method("GameLevelLoaded", 1).invoke(ugcLevelHash);
    }
    
    CheckCharacterControllerData_method.implementation = function (character: any) {
    
        FallGuysCharacterController_stored = character;
        CharacterControllerData_stored = character.method("get_Data").invoke(); // get Data instance
        JumpMotorFunction_stored = character.method("get_JumpMotorFunction").invoke(); // get JumpMotorFunction 
    
        CharacterControllerData_stored.field("divePlayerSensitivity").value = enable360Dives ? 14888 : 70;
        CharacterControllerData_stored.field("normalMaxSpeed").value = enableCustomSpeed ? customNormalMaxSpeed : 9.5;
    
        CharacterControllerData_stored.field("maxGravityVelocity").value = enableCustomVelocity
            ? enableNoVelocity
                ? 0
                : enableNegativeVelocity
                  ? -customMaxGravityVelocity
                  : customMaxGravityVelocity
            : 40;

        CharacterControllerData_stored.field("diveForce").value = enableCustomDiveForce ? customDiveForce : 17.5;
        CharacterControllerData_stored.field("airDiveForce").value = enableCustomDiveForce ? customDiveForce : 7;

        const jumpForce = JumpMotorFunction_stored.field<Il2Cpp.Object>("_jumpForce").value;
        jumpForce.field("y").value = enableCustomJump ? customJumpForceUltimateParty : 17.5;
    
        return true;
    };

    // functions 
    const FGDebug = {
        enable() {
            enableFGDebug = true;

            if (!reachedMainMenu) {
                return; // it will enable after hook
            }

            try {
                FGDebugInstance = findObjectsOfTypeAll(DebugClass).get(0); // find object with debug class

                const localScale = Vector3class.alloc().unbox();
                localScale.method(".ctor", 3).invoke(0.4, 0.4, 0.4); // new scale

                FGDebugInstance.method<Il2Cpp.Object>("get_transform").invoke().method<Il2Cpp.Object>("set_localScale").invoke(localScale);

                const gameObject = FGDebugInstance.method<Il2Cpp.Object>("get_gameObject").invoke();
                gameObject.method("SetActive").invoke(true); // enabling
            } catch (error: any) {
                Menu.toast(error.stack, 1);
                console.error(error.stack);
            }
        },
        disable() {
            enableFGDebug = false;
            FGDebugInstance = findObjectsOfTypeAll(DebugClass).get(0);
            if (FGDebugInstance) {
                const gameObject = FGDebugInstance.method<Il2Cpp.Object>("get_gameObject").invoke();
                gameObject.method("SetActive").invoke(false);
            }
        },
    };

    const findObjectsOfTypeAll = (klass: Il2Cpp.Class) => {
        return Resources.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1).invoke(klass.type.object);
    };

    const teleportToFinish = () => {
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
            const FinishVector3Pos = FinishObject
                .method<Il2Cpp.Object>("get_transform")
                .invoke()
                .method<Il2Cpp.Object>("get_position")
                .invoke();
    
            FallGuysCharacterController_stored
                //@ts-ignore
                .method<Il2Cpp.Object>("get_transform")
                .invoke()
                .method<Il2Cpp.Object>("set_position")
                .invoke(FinishVector3Pos);
        } else {
            Menu.toast(`No Finish or Crown was found. Round probably does not have a finish or a crown.`, 0);
        }
    };

    // buttons tested, bubbles no, give feedback
    const TeleportToScorePoint = () => {
        const BubblesArray = findObjectsOfTypeAll(SpawnableCollectable); // bubbles 
        const ScoredButtonArray = findObjectsOfTypeAll(ScoredButton);

        const teleportTo = (target: Il2Cpp.Object) => {
            const pos = target
                .method<Il2Cpp.Object>("get_transform")
                .invoke()
                .method<Il2Cpp.Object>("get_position")
                .invoke();
    
            FallGuysCharacterController_stored
                //@ts-ignore
                .method<Il2Cpp.Object>("get_transform")
                .invoke()
                .method<Il2Cpp.Object>("set_position")
                .invoke(pos);
        };

        for (const bubble of BubblesArray) {
            if (bubble.method<boolean>("get_Spawned").invoke()) {
                teleportTo(bubble);
                return;
            }
        }

        for (const button of ScoredButtonArray) {
            if (button.field<boolean>("_isAnActiveTarget").value) {
                teleportTo(button);
                return;
            }
        }

        Menu.toast("No bubbles or Buttons was found. If round has any, it's bug, open issue", 0);
    };

    const TeleportToRandomPlayer = () => {
        const FallGuysCharacterControllerArray = findObjectsOfTypeAll(FallGuysCharacterController); 

        if (FallGuysCharacterControllerArray.length > 0) {
            const randomIndex = Math.floor(Math.random() * FallGuysCharacterControllerArray.length); // random
            const randomPlayer = FallGuysCharacterControllerArray.get(randomIndex);

            const randomPlayerVector3Pos = randomPlayer
                .method<Il2Cpp.Object>("get_transform")
                .invoke()
                .method<Il2Cpp.Object>("get_position")
                .invoke();
        
            FallGuysCharacterController_stored
                //@ts-ignore
                .method<Il2Cpp.Object>("get_transform")
                .invoke()
                .method<Il2Cpp.Object>("set_position")
                .invoke(randomPlayerVector3Pos);
        } else {
            Menu.toast(`No Players found!`, 0);
        };
    };

    const changeResolutionScale = () => {
        try {
            console.log("trying change resolution scale to", customResolutionScale);
            GraphicsSettingsInstance.method("set_ResolutionScale", 1).invoke(customResolutionScale);
            /*
            i wanted to make this value changeable in the game, but unfortunately 
            calling ResolutionScaling::UpdateResolutionScaleStatus() doesn't do anything,
            maybe i should call something else, but idk exactly (will check later with IDA)
            */
        } catch (error: any) {
            Menu.toast(error.stack, 1); 
            console.error(error.stack);
        }

    }


    const initMenu = () => {
        try {
            const layout = new Menu.ObsidianLayout(obsidianConfig);
            const composer = new Menu.Composer("Fall Guys Mod Menu", "IF YOU BOUGHT IT YOU ARE SCAMMED", layout);
            composer.icon("https://floyzi.github.io/images/obed-guys-present.png", "Web");

            // movement
            const movement = layout.textView("<b>--- Movement ---</b>");
            movement.gravity = Menu.Api.CENTER;
            Menu.add(movement);

            Menu.add(
                layout.toggle("360 Dives", (state: boolean) => {
                    enable360Dives = state;
                    console.log(`enable360Dives: ${enable360Dives}`);
                }),
            );

            Menu.add(
                layout.toggle("Use Custom Speed", (state: boolean) => {
                    enableCustomSpeed = state;
                    console.log(`enableCustomSpeed: ${enableCustomSpeed}`);
                }),
            );

            Menu.add(
                layout.seekbar("Custom Speed: {0} / 100", 100, 1, (value: number) => {
                    customNormalMaxSpeed = value;
                    console.log(`customNormalMaxSpeed: ${customNormalMaxSpeed}`);
                }),
            ); 

            Menu.add(
                layout.toggle("Use Custom Velocity", (state: boolean) => {
                    enableCustomVelocity = state;
                    console.log(`enableCustomVelocity: ${enableCustomVelocity}`);
                }),
            );

            Menu.add(
                layout.seekbar("Vertical Gravity Velocity: {0} / 100", 100, 0, (value: number) => {
                    customMaxGravityVelocity = value;
                    console.log(`customMaxGravityVelocity: ${customMaxGravityVelocity}`);
                }),
            );

            Menu.add(
                layout.toggle("Negative Velocity", (state: boolean) => {
                    enableNegativeVelocity = state;
                    console.log(`enableNegativeVelocity: ${enableNegativeVelocity}`);
                }),
            );

            Menu.add(
                layout.toggle("No Velocity", (state: boolean) => {
                    enableNoVelocity = state;
                    console.log(`enableNoVelocity: ${enableNoVelocity}`);
                }),
            );

            Menu.add(
                layout.toggle("Use Custom Jump Strenght", (state: boolean) => {
                    enableCustomJump = state;
                    console.log(`enableCustomJump: ${enableCustomJump}`);
                }),
            );

            Menu.add(
                layout.seekbar("Jump Strenght: {0} / 100", 100, 1, (value: number) => {
                    customJumpForceUltimateParty = value;
                    console.log(`customJumpForceUltimateParty: ${customJumpForceUltimateParty}`);
                }),
            );

            Menu.add(
                layout.toggle("Use Custom Dive Strenght", (state: boolean) => {
                    enableCustomDiveForce = state;
                    console.log(`enableDiveForce: ${enableCustomDiveForce}`);
                }),
            );

            Menu.add(
                layout.seekbar("Dive Strenght: {0} / 100", 100, 1, (value: number) => {
                    customDiveForce = value;
                    console.log(`customDiveForce: ${customDiveForce}`);
                }),
            );

            // round
            const round = layout.textView("<b>--- Round ---</b>");
            round.gravity = Menu.Api.CENTER;
            Menu.add(round);

            Menu.add(
                layout.toggle("Hide Fake Doors, Tiptoe Platforms", (state: boolean) => {
                    enableHideStuff = state;
                    console.log(`enableHideStuff: ${enableHideStuff}`);
                }),
            );

            // teleports
            const teleports = layout.textView("<b>--- Teleports ---</b>");
            teleports.gravity = Menu.Api.CENTER;
            Menu.add(teleports);
            
            Menu.add(layout.button("Teleport To Finish or Crown", teleportToFinish));

            Menu.add(layout.button("Teleport To Random Player", TeleportToRandomPlayer));

            Menu.add(layout.button("Teleport To Bubble or Active Button", TeleportToScorePoint));

            // other
            const other = layout.textView("<b>--- Other ---</b>");
            other.gravity = Menu.Api.CENTER;
            Menu.add(other);

            Menu.add(
                layout.toggle("Display FGDebug", (state: boolean) => {
                    state ? FGDebug.enable() : FGDebug.disable();
                }),
            );

            Menu.add(
                layout.seekbar("Custom Resolution (Applied in Next Round): {0}% / 100%", 100, 1, (value: number) => {
                    customResolutionScale = value / 100;
                    changeResolutionScale(); 
                    console.log(`customResolutionScale: ${customResolutionScale}`);
                }),
            );

            // links
            const links = layout.textView("<b>--- Links ---</b>");
            links.gravity = Menu.Api.CENTER;
            Menu.add(links);

            Menu.add(layout.button("Github Repository (Leave a star!)", () => openURL("https://github.com/repinek/fallguys-frida-modmenu")));
            Menu.add(layout.button("Cheating Discord Server", () => openURL("https://discord.gg/cNFJ73P6p3")));
            Menu.add(layout.button("Creator's Twitter", () => openURL("https://x.com/repinek840")));

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
