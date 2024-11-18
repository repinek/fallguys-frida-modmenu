import 'frida-il2cpp-bridge';
import 'frida-java-menu';
import { obsidianConfig } from './menuConfig.js';

// ultra shitcode at least it works
let AssemblyCSharp: Il2Cpp.Image | undefined;
let TheMultiplayerGuys: Il2Cpp.Image | undefined;
let CoreModule: Il2Cpp.Image | undefined;

let Resources: Il2Cpp.Class | undefined; 

function getAssemblyCSharp() {
  console.log(2)
  if (AssemblyCSharp) return AssemblyCSharp;
  AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image;
  return AssemblyCSharp;
}

function getCoreModule() {
    if (CoreModule) return CoreModule;
    CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
    Resources = CoreModule.class("UnityEngine.Resources")
    return CoreModule;
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

function findObjectsOfTypeAll(klass: Il2Cpp.Class) {
    return Resources!.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1,).invoke(klass.type.object);
  }

function TeleportToEndZone() {
    let instance: Il2Cpp.Object | null = null;
    try {
      const ObjectiveReachEndZone = TheMultiplayerGuys!.class('FG.Common.COMMON_ObjectiveReachEndZone');
      instance = findObjectsOfTypeAll(ObjectiveReachEndZone).get(0);
      console.log(instance);
      if (instance) {
        const EndZoneVector3Pos = instance
        .method<Il2Cpp.Object>("get_transform").invoke()
        .method<Il2Cpp.Object>("get_position").invoke();

        storedFallGuysCharacterController!.
        //@ts-ignore
        method<Il2Cpp.Object>("get_transform").invoke().
        method<Il2Cpp.Object>("set_position").invoke(EndZoneVector3Pos);
      }

    } catch (error) {
      console.error("EndZone instance not found. Probably round is not Race. Error:", error);
    }
}

function init() {
    try {
        Il2Cpp.perform(getAssemblyCSharp);
        Il2Cpp.perform(getCoreModule);
        
        const layout = new Menu.ObsidianLayout(obsidianConfig);
        const composer = new Menu.Composer("FGStool Mobile", "Created by @repinek", layout);
        composer.icon("https://cdn.floyzi.ru/shared-images/fgstool2.png", "Web");

        const general = layout.textView("<b>--- Physics ---</b>");
        general.gravity = Menu.Api.CENTER;

        Menu.add(general);

        Menu.add(layout.toggle("Bypass Character Controller Data checks", (enabled) => {
            toggleCheckCharacterControllerDataBypass(enabled);
        }));

        Menu.add(layout.toggle("360 Dives", (enabled) => {
            enabled ? is360Dives = true : is360Dives = false;
        }));
        
        Menu.add(
          layout.seekbar("Normal Max Speed: {0} / 1000", 100, 1, (value: number) => { 
              normalMaxSpeed = value;
              console.log(`Normal Max Speed updated: ${normalMaxSpeed}`);
            }));
        
        Menu.add(layout.toggle("No Velocuty", (enabled) => {
              enabled ? noVelocity = true : noVelocity = false;
          }));

        Menu.add(
          layout.seekbar("Max Gravity Velocity: {0} / 100", 100, -100, (value: number) => {  // -100 dont work
              maxGravityVelocity = value;
              console.log(`Max Gravity Velocity updated: ${maxGravityVelocity}`);
            }));
            
        Menu.add(layout.button("Teleport to Finish (Only Races)", () => TeleportToEndZone()));
        
        Menu.toast("Created by repinek", 1);
        
        composer.show();
    } catch (error: any) {
        console.log(error.stack);
    }
}

Menu.waitForInit(init);
