import { Logger } from "../logger/logger.js";

export class AssemblyHelper {
    public static MediatonicCatapultClientSdkRuntime: Il2Cpp.Image; // Catapult namespace & network related
    public static TheMultiplayerGuys: Il2Cpp.Image; // FG.Common
    public static MTFGClient: Il2Cpp.Image; // FGClient
    public static CoreModule: Il2Cpp.Image; // UnityEngine
    public static UI: Il2Cpp.Image; // UnityEngine
    public static UIModule: Il2Cpp.Image; // UnityEngine
    public static TextRenderingModule: Il2Cpp.Image; // UnityEngine

    public static init() {
        this.MediatonicCatapultClientSdkRuntime = Il2Cpp.domain.assembly("Mediatonic.Catapult.ClientSdk.Runtime").image;
        this.TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image;
        this.MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image;
        this.CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
        this.UI = Il2Cpp.domain.assembly("UnityEngine.UI").image;
        this.UIModule = Il2Cpp.domain.assembly("UnityEngine.UIModule").image;
        this.TextRenderingModule = Il2Cpp.domain.assembly("UnityEngine.TextRenderingModule").image;

        Logger.info("[AssemblyHelper] Initialized");
    }
}
