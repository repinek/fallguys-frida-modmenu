import { Logger } from "../utils/logger.js";

export class AssemblyHelper {
    public static MediatonicCatapultClientSdkRuntime: Il2Cpp.Image; // Catapult namespace & network related
    public static TheMultiplayerGuys: Il2Cpp.Image; // FG.Common
    public static MTFGClient: Il2Cpp.Image; // FGClient
    public static CoreModule: Il2Cpp.Image; // UnityEngine

    public static init() {
        this.MediatonicCatapultClientSdkRuntime = Il2Cpp.domain.assembly("Mediatonic.Catapult.ClientSdk.Runtime").image;
        this.TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image;
        this.MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image;
        this.CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;

        Logger.info("[AssemblyHelper] Initialized");
    }
}
