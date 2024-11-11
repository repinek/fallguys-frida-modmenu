import 'frida-il2cpp-bridge';
import { 
    getActivity, sleep, ensureModuleInitialized, JavaIl2cppPerform, FallGuysToolsImage
} 
from './util.js';

type Il2CppThis = Il2Cpp.Class | Il2Cpp.Object;

const APP_MAIN_ACTIVITY = "com.unity3d.player.UnityPlayerActivity"

const modules = ['libil2cpp.so', 'libunity.so', 'libmain.so'];

JavaIl2cppPerform(async () => {
  await sleep(1000);
  await ensureModuleInitialized(...modules);

  const mainActivity = await getActivity(APP_MAIN_ACTIVITY);
  if (!mainActivity) throw new Error('Failed to get main activity');

  main(mainActivity).catch((error) => console.error(error));
});

async function main(mainActivity: Java.Wrapper) {

  // Getting Java classes

  const Menu = Java.use('com.maars.fmenu.Menu');
  const Config = Java.use('com.maars.fmenu.Config');
  const Bool = Java.use('com.maars.fmenu.PBoolean');
  const Int = Java.use('com.maars.fmenu.PInteger');

	// Getting unity classes

	const TheMultiplayerGuys = Il2Cpp.domain.assembly('TheMultiplayerGuys.FGCommon');
  const CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;

  const Resources = CoreModule.class("UnityEngine.Resources");
	const CharacterDataMonitor = TheMultiplayerGuys.image.class('FG.Common.Character.CharacterDataMonitor');
	const CharacterControllerData = TheMultiplayerGuys.image.class('FG.Common.CharacterControllerData');
  await sleep(1000); // try to fix random crashes while image.class('FG.Common.COMMON_ObjectiveReachEndZone'); // not working ig
  const ObjectiveReachEndZone = TheMultiplayerGuys.image.class('FG.Common.COMMON_ObjectiveReachEndZone');

	// Creating state variables

  const isBypassCCH = Bool.of(false);
	const is360Dives = Bool.of(false);
	const normalMaxSpeedvalue = Int.of(9);
	const maxGravityVelocityvalue = Int.of(40);
  const tpToEndZonevalue = Bool.of(false);

  // Creating a custom config

  const config = Config.$new();

  config.MENU_SUBTITLE.value = 'Created By @repinek';

  const menu = Menu.$new(mainActivity, config);

  // Building menu

  menu.Switch('Bypass CharacterControllerData Checks', isBypassCCH);
	menu.Switch('360 Dives', is360Dives);
	menu.SeekBar('Normal Max Speed', normalMaxSpeedvalue, 1, 1000);
	menu.SeekBar('Max Gravity Velocity', maxGravityVelocityvalue, -100, 200);
  menu.Switch('Teleport To Finish', tpToEndZonevalue);

	// Main functions, hooks

  function findObjectsOfTypeAll(klass: Il2Cpp.Class) {
    return Resources.method<Il2Cpp.Array<Il2Cpp.Object>>("FindObjectsOfTypeAll", 1,).invoke(klass.type.object);
  }

	let storedCharacterControllerData = null;
	
  // FallGuysCharacterController character
	CharacterDataMonitor.method("CheckCharacterControllerData", 1).implementation = function (character) {
    console.log("Перехвачена функция CheckCharacterControllerData");
    if (isBypassCCH.get()) {
        console.log("52")
        // Set variables from menu
        //@ts-ignore for character.method
        let storedCharacterControllerData = character.method("get_Data").invoke();
				storedCharacterControllerData.field("normalMaxSpeed").value = normalMaxSpeedvalue.get(); 
				storedCharacterControllerData.field("maxGravityVelocity").value = maxGravityVelocityvalue.get(); 
				console.log(storedCharacterControllerData.field("normalMaxSpeed").value) 
				if (is360Dives.get()){
					storedCharacterControllerData.field("divePlayerSensitivity").value = 14888; // Set divePlayerSensivity to 14888 (for 360 dives)
				}
        if (tpToEndZonevalue.get()) {
          let instance = findObjectsOfTypeAll(ObjectiveReachEndZone).get(0)
          const EndZoneVector3Pos = instance
          .method<Il2Cpp.Object>("get_transform").invoke()
          .method<Il2Cpp.Object>("get_position").invoke();

          console.log(EndZoneVector3Pos)
          //@ts-ignore
          console.log(character.monitor)

          character.
          //@ts-ignore
          method<Il2Cpp.Object>("get_transform").invoke().
          method<Il2Cpp.Object>("set_position").invoke(EndZoneVector3Pos);
        }
          // flag2 = isValid; return flag2; 
          return true;
    } else {
        return this.method("CheckCharacterControllerData", 1).invoke(character); // dont change method if not enabled 
    }
};

Java.scheduleOnMainThread(() => {
  sleep(2000) // idk gonna try to fix crashes // not working ig
  menu.attach();
});
}