import { Logger } from "../utils/Logger";

export class AssemblyHelper {
    static MediatonicCatapultClientSdkRuntime: Il2Cpp.Image; // Catapult namespace & network related
    static TheMultiplayerGuys: Il2Cpp.Image; // FG::Common
    static MTFGClient: Il2Cpp.Image; // FGClient
    static CoreModule: Il2Cpp.Image; // UnityEngine
    static TextMeshPro: Il2Cpp.Image; // TMPro
    static DOTween: Il2Cpp.Image; // DG::Tweening

    static init() {
        this.MediatonicCatapultClientSdkRuntime = Il2Cpp.domain.assembly("Mediatonic.Catapult.ClientSdk.Runtime").image;
        this.TheMultiplayerGuys = Il2Cpp.domain.assembly("TheMultiplayerGuys.FGCommon").image;
        this.MTFGClient = Il2Cpp.domain.assembly("MT.FGClient").image;
        this.CoreModule = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image;
        this.TextMeshPro = Il2Cpp.domain.assembly("Unity.TextMeshPro").image;
        this.DOTween = Il2Cpp.domain.assembly("DOTween").image;

        Logger.info("[AssemblyHelper::init] Initialized");
    }
}
