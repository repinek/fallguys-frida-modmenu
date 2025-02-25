import 'frida-il2cpp-bridge';
import 'frida-java-menu';
import { obsidianConfig } from './menuConfig.js';

// assemblies
let TheMultiplayerGuys: Il2Cpp.Image | undefined;
let CoreModule: Il2Cpp.Image | undefined;
let MTFGClient: Il2Cpp.Image | undefined;

// classes
let Resources: Il2Cpp.Class | undefined; 
let Vector3class: Il2Cpp.Class | undefined; 
let GraphicsSettings: Il2Cpp.Class | undefined;
let LobbyService: Il2Cpp.Class | undefined;
let CharacterDataMonitor: Il2Cpp.Class | undefined; 
let DebugClass: Il2Cpp.Class | undefined;
let ObjectiveReachEndZone: Il2Cpp.Class | undefined;

// storage
let reachedMainMenu = false;
let FallGuysCharacterController_stored: Il2Cpp.Class | undefined;
let CharacterControllerData_stored: Il2Cpp.Class | undefined;
let FGDebugInstance: Il2Cpp.Object | null = null;

function prepareModules() {
  /*
  sooo, if you load all these assemblies before the menu appears, the game will freeze when entering the main menu. 
  probably, the shitcode from the menu is affecting this, idk.

  you can load the menu here, in this function, and it will wait another 2 seconds in the initMenu function before showing it (bad, but working SOMETIMES), 
  or you can load the menu when entering the main menu in the OnMainMenuDisplayed_method hook.
  */

  //Menu.waitForInit(initMenu);
  Menu.toast("Menu will appear once you enter the main menu.", 1);

  CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
  Resources = CoreModule.class("UnityEngine.Resources");
  Vector3class = CoreModule.class("UnityEngine.Vector3");

  MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image;
  GraphicsSettings = MTFGClient.class("FGClient.GraphicsSettings");
  LobbyService = MTFGClient.class("FGClient.CatapultServices.LobbyService");

  TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image;
  CharacterDataMonitor = TheMultiplayerGuys.class("FG.Common.Character.CharacterDataMonitor");
  DebugClass = TheMultiplayerGuys.class('GvrFPS');
  ObjectiveReachEndZone = TheMultiplayerGuys.class('FG.Common.COMMON_ObjectiveReachEndZone');


  console.log("Loaded assemblies and classes");
  Il2Cpp.perform(functionHooks);
  return
}

function functionHooks() {
  const OnMainMenuDisplayed_method = LobbyService!.method("OnMainMenuDisplayed", 1); 
  const CheckCharacterControllerData_method = CharacterDataMonitor!.method("CheckCharacterControllerData", 1);
  const get_TargetFrameRate_method = GraphicsSettings!.method("get_TargetFrameRate", 0); 
  const set_TargetFrameRate_method = GraphicsSettings!.method("set_TargetFrameRate", 1);

  get_TargetFrameRate_method.implementation = function() {
    console.log("get_TargetFrameRate Called!");
    return 1488 // fps
  }

  set_TargetFrameRate_method.implementation = function (fps) {
    console.log("set_TargetFrameRate Called!");
    return this.method<void>("set_TargetFrameRate", 1).invoke(1488); 
  }

  OnMainMenuDisplayed_method.implementation = function(event) {
      console.log("OnMainMenuDisplayed Called!");

      if (!reachedMainMenu) {
        Menu.toast("Showing menu", 0);
        Menu.waitForInit(initMenu);
        reachedMainMenu = true;
        if (enableFGDebug) {
          FGDebug.enable();
        }
      }

      return this.method<void>("OnMainMenuDisplayed", 1).invoke(event);
  } 

  // update function
  CheckCharacterControllerData_method.implementation = function(character: any) {
      console.log("CheckCharacterControllerData Called!");
      FallGuysCharacterController_stored = character;
      CharacterControllerData_stored = character.method("get_Data").invoke(); // get Data instance

      CharacterControllerData_stored!.field("divePlayerSensitivity").value = enable360Dives ? 14888 : 70;
      CharacterControllerData_stored!.field("normalMaxSpeed").value = enableCustomSpeed ? customNormalMaxSpeed : 9.5;

      CharacterControllerData_stored!.field("maxGravityVelocity").value = enableCustomVelocity
      ? (enableNoVelocity ? 0 : (enableNegativeVelocity ? -customMaxGravityVelocity : customMaxGravityVelocity))
      : 40;

      /*  
      about JumpForce  
      value that needs to be changed is located in JumpMotorFunction within FallGuysCharacterController_stored
      (don't forget to use get, since it's a getter method)  

      const jumpforce = JumpMotorFunction_stored!.method<Il2Cpp.Object>("get_JumpForce").invoke() as any;  
      console.log(jumpforce.field("y").value);  

      however, i couldn't change it.  
      jumpforce.field("y").value = 100;  
      didn't work
      tried set, but nothing too  
      */

      const jumpForce = CharacterControllerData_stored!.field<Il2Cpp.Object>("jumpForceUltimateParty").value;
      jumpForce.field("y").value = enableCustomJump ? customJumpForceUltimateParty : 17.5;

      return true;
  }
}

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

function findObjectsOfTypeAll(klass: Il2Cpp.Class) {
  return Resources!.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1,).invoke(klass.type.object);
}

// enablers
let enable360Dives: boolean;
let enableCustomSpeed: boolean;
let enableCustomVelocity: boolean;
let enableNegativeVelocity: boolean;
let enableNoVelocity: boolean;
let enableCustomJump: boolean;
let enableFGDebug: boolean;

// player
let customNormalMaxSpeed = 9.5;
let customMaxGravityVelocity = 40;
let customJumpForceUltimateParty = 17.5;

// other
function TeleportToEndZone() {
    let endZoneInstance: Il2Cpp.Object | null = null;

    try {
      endZoneInstance = findObjectsOfTypeAll(ObjectiveReachEndZone!).get(0); // find finish

      if (endZoneInstance) {
        const EndZoneVector3Pos = endZoneInstance 
        .method<Il2Cpp.Object>("get_transform").invoke()
        .method<Il2Cpp.Object>("get_position").invoke(); 

        FallGuysCharacterController_stored!.
        //@ts-ignore
        method<Il2Cpp.Object>("get_transform").invoke().
        method<Il2Cpp.Object>("set_position").invoke(EndZoneVector3Pos);
      }

    } catch (error: any) {
      Menu.toast(`No EndZone instance was found. The round is probably not a race or it has not started yet`, 0);
      console.error(error.stack)
    }
}

const FGDebug = {
  enable() {
    enableFGDebug = true;

    if (!reachedMainMenu) {
      return // it will enable after hook
    } 

    try {
      FGDebugInstance = findObjectsOfTypeAll(DebugClass!).get(0); // find object with debug class
      
      const localScale = Vector3class!.alloc().unbox();
      localScale.method(".ctor", 3).invoke(0.4, 0.4, 0.4); // new scale

      FGDebugInstance
      .method<Il2Cpp.Object>("get_transform").invoke()
      .method<Il2Cpp.Object>("set_localScale").invoke(localScale); 

      const gameObject = FGDebugInstance.method<Il2Cpp.Object>("get_gameObject").invoke(); 
      gameObject.method("SetActive").invoke(true); // enabling

    } catch (error: any) {
      Menu.toast(error.stack, 1);
      console.error(error.stack)
    }

  },
  disable() {
    enableFGDebug = false;
    FGDebugInstance = findObjectsOfTypeAll(DebugClass!).get(0);
    if (FGDebugInstance) {
      const gameObject = FGDebugInstance.method<Il2Cpp.Object>("get_gameObject").invoke(); 
      gameObject.method("SetActive").invoke(false);
    }
  }
} 

function initMenu() {
    try {
        const layout = new Menu.ObsidianLayout(obsidianConfig);
        const composer = new Menu.Composer("Fall Guys Mod Menu", "Created by @repinek", layout);
        composer.icon("https://floyzi.github.io/images/sigma.png", "Web");

        // Physics 
        const general = layout.textView("<b>--- Physics ---</b>");
        general.gravity = Menu.Api.CENTER;
        Menu.add(general);

        Menu.add(layout.toggle("360 Dives", (state: boolean) => {
          enable360Dives = state;
          console.log(`enable360Dives: ${enable360Dives}`);
        }));
      
        Menu.add(layout.toggle("Use Custom Speed", (state: boolean) => {
          enableCustomSpeed = state;
          console.log(`enableCustomSpeed: ${enableCustomSpeed}`);
        }))

        Menu.add(
          layout.seekbar("Normal Max Speed: {0} / 100", 100, 1, (value: number) => { 
            customNormalMaxSpeed = value;
            console.log(`customNormalMaxSpeed: ${customNormalMaxSpeed}`);
        }));
        
        Menu.add(layout.toggle("Use Custom Velocity", (state: boolean) => {
          enableCustomVelocity = state;
          console.log(`enableCustomVelocity: ${enableCustomVelocity}`)
        }));
    
        Menu.add(
          layout.seekbar("Max Gravity Velocity: {0} / 100", 100, -100, (value: number) => {
            customMaxGravityVelocity = value;
            console.log(`customMaxGravityVelocity: ${customMaxGravityVelocity}`);
        }));
        
        Menu.add(layout.toggle("Negative Velocity", (state: boolean) => {
          enableNegativeVelocity = state;
          console.log(`enableNegativeVelocity: ${enableNegativeVelocity}`)
        }));
        
        Menu.add(layout.toggle("No Velocity", (state: boolean) => {
          enableNoVelocity = state;
          console.log(`enableNoVelocity: ${enableNoVelocity}`)
        }));

        Menu.add(layout.toggle("Use Custom Jump Force (Applied in Next Round)", (state: boolean) => {
          enableCustomJump = state;
          console.log(`enableCustomJump: ${enableCustomJump}`)
        }))

        Menu.add(
          layout.seekbar("Jump Force: {0} / 100", 100, 1, (value: number) => { 
            customJumpForceUltimateParty = value;
            console.log(`customJumpForceUltimateParty: ${customJumpForceUltimateParty}`);
        }));
        
        Menu.add(layout.button("Teleport to Finish (Only Races)", () => TeleportToEndZone()));
        
        // other
        const other = layout.textView("<b>--- Other ---</b>");
        other.gravity = Menu.Api.CENTER;
        Menu.add(other);

        Menu.add(layout.toggle("Display FGDebug", (state: boolean) => {
          state ? FGDebug.enable() : FGDebug.disable();
        }));

        // links
        const links = layout.textView("<b>--- Links ---</b>");
        links.gravity = Menu.Api.CENTER;
        Menu.add(links);

        Menu.add(layout.button("Github Repository (Leave a star!)", () => openURL("https://github.com/repinek/FallGuysFridaModMenu")));
        Menu.add(layout.button("Creator's Twitter", () => openURL("https://x.com/repinek840")))

        Java.scheduleOnMainThread(() => {
          setTimeout(() => {
              composer.show();
          }, 2000) // refer to the comment in the prepareModules function
        }) 

    } catch (error: any) {
        Menu.toast(error.stack, 1);
        console.error(error.stack)
    }
}

Il2Cpp.perform(prepareModules);