import 'frida-il2cpp-bridge';
import 'frida-java-menu';
import { obsidianConfig } from './menuConfig.js';

// ultra shitcode at least it works
let AssemblyCSharp: Il2Cpp.Image | undefined;
let TheMultiplayerGuys: Il2Cpp.Image | undefined;
let CoreModule: Il2Cpp.Image | undefined;
let MTFGClient: Il2Cpp.Image | undefined;

let Resources: Il2Cpp.Class | undefined; 
let GraphicsSettings: Il2Cpp.Class | undefined;

function getAssemblyCSharp() {
  console.log(2)
  if (AssemblyCSharp) return AssemblyCSharp;
  AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
  return AssemblyCSharp;
}

function getCoreModule() {
  if (CoreModule) return CoreModule;
  CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
  Resources = CoreModule.class("UnityEngine.Resources");
  return CoreModule;
  }

function getMTFGClient() {
  if (MTFGClient) return MTFGClient;
  MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image;
  GraphicsSettings = MTFGClient.class("FGClient.GraphicsSettings")
  return MTFGClient;
}


// Helper functions
function OpenURL(link: string) {
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


let storedFallGuysCharacterController = Il2Cpp.Class;

let isCharacterControllerDataCheckEnabled = false;
let originalCheckCharacterControllerData: Il2Cpp.Method | null = null; 
let CharacterDataMonitor: Il2Cpp.Class | undefined; 
let storedCharacterControllerData: Il2Cpp.Class | undefined;

// from menu 
let is360Dives = false;
let timetospawn = 10000;
let normalMaxSpeed = 9.5;
let maxGravityVelocity = 40; 
let noVelocity = false;
let removeFPSLimit = false;

const CheckCharacterControllerDataBypass = {
    enable() {
        try {
            console.log("[Disable] CheckCharacterControllerDataBypass");

            Java.scheduleOnMainThread(() => {
                console.log("[Disable] Preparing to hook CheckCharacterControllerData...");

                setTimeout(() => {
                    console.log("[Disable] Delayed execution before implementation");
                    const method = CharacterDataMonitor!.method("CheckCharacterControllerData", 1);

                    if (originalCheckCharacterControllerData === null) {
                        originalCheckCharacterControllerData = method;
                    }
                    
                    // FallGuysCharacterController character
                    method.implementation = function (character: any) {
                        console.log("[Disable] Method CheckCharacterControllerData called");
                        storedFallGuysCharacterController = character;

                        storedCharacterControllerData = character.method("get_Data").invoke();

                        if (is360Dives === true) {
                            storedCharacterControllerData!.field("divePlayerSensitivity").value = 14888;
                        }
                        else if (is360Dives === false) {
                            storedCharacterControllerData!.field("divePlayerSensitivity").value = 70;
                        }
                        
                        storedCharacterControllerData!.field("normalMaxSpeed").value = normalMaxSpeed;
                        
                        if (noVelocity === false) {
                          storedCharacterControllerData!.field("maxGravityVelocity").value = maxGravityVelocity;
                        }
                        else if (noVelocity === true) {
                          storedCharacterControllerData!.field("maxGravityVelocity").value = 0;
                        }
                        return isCharacterControllerDataCheckEnabled ? true : originalCheckCharacterControllerData!.invoke(character);
                    };
                    timetospawn = 0;
                    console.log("[Disable] Hook successfully applied to CheckCharacterControllerData!");
                }, timetospawn); // эти краши чертовски пиздец.
            });

        } catch (error: any) {
            console.log(error);
        }
    },

    disable() {
        console.log("[Disable] CheckCharacterControllerDataBypass 525252");

        if (originalCheckCharacterControllerData) {
            originalCheckCharacterControllerData.revert();
            originalCheckCharacterControllerData = null; 
        }
    }
};


function toggleCheckCharacterControllerDataBypass(enabled: boolean) {
    isCharacterControllerDataCheckEnabled = enabled;

    Java.scheduleOnMainThread(() => {
        console.log("Scheduling execution in 10 seconds...");

        setTimeout(() => {
            if (TheMultiplayerGuys) {
                console.log("TheMultiplayerGuys.FGCommon already loaded.");
                CharacterDataMonitor = TheMultiplayerGuys!.class("FG.Common.Character.CharacterDataMonitor");
                Il2Cpp.perform(() => {
                    enabled ? CheckCharacterControllerDataBypass.enable() : CheckCharacterControllerDataBypass.disable();
                });
                return;
            }

            console.log("Waiting for TheMultiplayerGuys.FGCommon to load...");

            // Пока ассембля не загрузится
            while (!TheMultiplayerGuys) {
                TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image;
                if (!TheMultiplayerGuys) {
                    console.log("Still waiting for TheMultiplayerGuys.FGCommon...");
                }
            }

            console.log("Successfully loaded TheMultiplayerGuys.FGCommon.");
            CharacterDataMonitor = TheMultiplayerGuys!.class("FG.Common.Character.CharacterDataMonitor");
            Il2Cpp.perform(() => {
                enabled ? CheckCharacterControllerDataBypass.enable() : CheckCharacterControllerDataBypass.disable();
            });
        }, timetospawn); 
    });
}


function TeleportToEndZone() {
    let instance: Il2Cpp.Object | null = null;

    try {
      const ObjectiveReachEndZone = TheMultiplayerGuys!.class('FG.Common.COMMON_ObjectiveReachEndZone');
      instance = findObjectsOfTypeAll(ObjectiveReachEndZone).get(0);
      if (instance) {
        console.log(`EndZone instance has been found ${instance}`);
        const EndZoneVector3Pos = instance 
        .method<Il2Cpp.Object>("get_transform").invoke()
        .method<Il2Cpp.Object>("get_position").invoke();

        storedFallGuysCharacterController!.
        //@ts-ignore
        method<Il2Cpp.Object>("get_transform").invoke().
        method<Il2Cpp.Object>("set_position").invoke(EndZoneVector3Pos);
      }

    } catch (error: any) {
      Menu.toast(`No EndZone instance was found. The round is probably not a race or it has not started yet`, 0);
      console.error(error.stack)
    }
}

// Other 
function FGDebugShow(enabled: boolean) {
  let instance: Il2Cpp.Object | null = null;

  try {
    const DebugClass = TheMultiplayerGuys!.class('GvrFPS');
    instance = findObjectsOfTypeAll(DebugClass).get(0); 

    if (instance) {
      console.log(`Debug instance has been found ${instance}`);
      const gameObject = instance.method<Il2Cpp.Object>("get_gameObject").invoke(); 
      gameObject.method("SetActive").invoke(true)
    } else {
      console.log("Debug instance not found");
    }
  } catch (error: any) {
    Menu.toast(error.stack, 1);
    console.error(error.stack);
  }
}

function RemoveFPSLimit() {
    // it would be good to do a check if the fps already changed
    const text = "To remove FPS Limit change the FPS preset in settings to any other and save. You need to do this only once!"

    if (removeFPSLimit === true) {
      Menu.toast(text, 1)
      return
    }

    removeFPSLimit = true;
    const method = GraphicsSettings!.method("set_TargetFrameRate", 1);
    method.implementation = function () {
      Menu.toast(text, 1)
      return this.method("set_TargetFrameRate", 1).invoke(1488); // 
    }
  }

// const FPSBypassnahoi = {
//   enable() {
//     const method = GraphicsSettings!.method("set_TargetFrameRate", 1);
//     method.implementation = function (value) {
//       return this.method("set_TargetFrameRate", 1).invoke(1488);
//     }
//   },
//   disable() {
//     console.warn("пидорас да хуй сосал да")
//   }
// }

function init() {
    try {
        Il2Cpp.perform(getAssemblyCSharp);
        Il2Cpp.perform(getCoreModule);
        Il2Cpp.perform(getMTFGClient)
        const layout = new Menu.ObsidianLayout(obsidianConfig);
        const composer = new Menu.Composer("Fall Guys Mod Menu", "Created by @repinek", layout);
        composer.icon("https://cdn.floyzi.ru/shared-images/fgstool2.png", "Web");

        // Physics 
        const general = layout.textView("<b>--- Physics ---</b>");
        general.gravity = Menu.Api.CENTER;
        Menu.add(general);

        Menu.add(layout.toggle("Bypass Character Controller Data checks", (enabled) => {
            toggleCheckCharacterControllerDataBypass(enabled);
        }));

        Menu.add(layout.toggle("360 Dives", (enabled) => {
            enabled ? is360Dives = true : is360Dives = false;
            console.log(`Is 360 Dives updated: ${is360Dives}`);
        }));
        
        Menu.add(
          layout.seekbar("Normal Max Speed: {0} / 100", 100, 1, (value: number) => { 
              normalMaxSpeed = value;
              console.log(`Normal Max Speed updated: ${normalMaxSpeed}`);
        }));
        
        Menu.add(layout.toggle("No Velocity", (enabled) => {
              enabled ? noVelocity = true : noVelocity = false;
              console.log(`No Velocity updated: ${noVelocity}`)
        }));

        Menu.add(
          layout.seekbar("Max Gravity Velocity: {0} / 100", 100, -100, (value: number) => {
              maxGravityVelocity = value;
              console.log(`Max Gravity Velocity updated: ${maxGravityVelocity}`);
        }));
            
        Menu.add(layout.button("Teleport to Finish (Only Races)", () => TeleportToEndZone()));
        
        // other
        const other = layout.textView("<b>--- Other ---</b>");
        other.gravity = Menu.Api.CENTER;
        Menu.add(other);

        Menu.add(layout.toggle("Display FGDebug", (enabled) => {
          FGDebugShow(enabled);
          console.log(`Display FGDebug turned on`)
        }));

        Menu.add(layout.button("Remove FPS Limit", () => RemoveFPSLimit()))

        // links
        const links = layout.textView("<b>--- Links ---</b>");
        links.gravity = Menu.Api.CENTER;
        Menu.add(links);

        Menu.add(layout.button("Github Repository", () => OpenURL("https://github.com/repinek/FallGuysFridaModMenu")));


        Menu.toast("Created by repinek", 1);
        composer.show();
    } catch (error: any) {
        Menu.toast(error.stack, 1);
    }
}

Menu.waitForInit(init);
