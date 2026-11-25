import { AssemblyHelper } from "../../../../engine/AssemblyHelper";
import { UnityUtils } from "../../../../engine/UnityUtils";
import { Vector3 } from "../../../../engine/wrappers/Vector3";
import { Logger } from "../../../../utils/Logger";
import { ModalMessageData } from "./data/ModalMessageData";
import { ModalMessageWithInputFieldData } from "./data/ModalMessageWithInputFieldData";
import { ModalMessageWithOptionSelectionData } from "./data/ModalMessageWithOptionSelectionData";

/*
 * Wrapper over FGClient::UI::PopupManager
 * Easily extendable to add other popups
 *
 * About scaling:
 * I tried to just change transform::localScale, but it was useless
 * Game uses TweenOnPopup component which animates opening using DOTween
 * TweenOnPopup::ScaleUp calls DOScale, so we just hook DOScale and change endValue vector3
 */

export class PopupManager {
    // Classes
    private static PopupManager: Il2Cpp.Class;
    private static _popupManagerInstance?: Il2Cpp.Object;

    private static ModalMessagePopupViewModel: Il2Cpp.Class;
    private static ModalMessageWithInputFieldViewModel: Il2Cpp.Class;
    private static ModalMessageWithOptionSelectionPopupViewModel: Il2Cpp.Class;

    // Enums
    private static PopupInteractionType: Il2Cpp.Class;
    private static _info: Il2Cpp.ValueType;

    private static waitingForScaling = false;
    private static scale: number;

    static init(): void {
        this.PopupManager = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupManager");

        this.ModalMessagePopupViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessagePopupViewModel");
        this.ModalMessageWithInputFieldViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithInputFieldViewModel");
        this.ModalMessageWithOptionSelectionPopupViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithOptionSelectionPopupViewModel");

        this.PopupInteractionType = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupInteractionType");

        const ShortcutExtensions = AssemblyHelper.DOTween.class("DG.Tweening.ShortcutExtensions");
        // @ts-ignore
        ShortcutExtensions.method("DOScale", 3).implementation = this.doScaleHook;

        Logger.info(`[PopupManager::init] Initialized`);
    }

    // TODO: return type
    // It's a bad implementation, but idk. Not always working!
    private static doScaleHook(this: Il2Cpp.Object, transform: Il2Cpp.Object, endValueVector3: Il2Cpp.ValueType, duration: number) {
        // Logger.hook("DOScale called with args:", transform, endValueVector3, duration);
        if (PopupManager.waitingForScaling) {
            const scale = PopupManager.scale;
            endValueVector3 = Vector3.create(scale, scale, scale);
        }

        return this.method("DOScale", 3).invoke(transform, endValueVector3, duration);
    }

    static show(ModalMessageData: ModalMessageData, scale?: number): void;

    static show(ModalMessageWithInputFieldData: ModalMessageWithInputFieldData, scale?: number): void;

    static show(ModalMessageWithOptionSelectionData: ModalMessageWithOptionSelectionData, scale?: number): void;

    /**
     * Shows in-game Popup (Modal Message)
     *
     * @param data Configuration object containing Title, Message, Buttons, etc. (use .create() to make one)
     * @param scale (Optional) Custom size of popup
     */
    static show(data: ModalMessageData | ModalMessageWithInputFieldData | ModalMessageWithOptionSelectionData, scale?: number): void {
        const ShowMethod = this.PopupManagerInstance!.method<boolean>("Show", 3).overload(
            "FGClient.UI.PopupInteractionType",
            "FGClient.UI.ModalMessageBaseData",
            "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
        );

        if (scale) {
            this.waitingForScaling = true;
            this.scale = scale;
        }

        if (data instanceof ModalMessageWithInputFieldData) {
            Logger.debug(`[PopupManager::show] Showing ModalMessageWithInputFieldData Popup`);
            ShowMethod.inflate(this.ModalMessageWithInputFieldViewModel).invoke(this.Info, data.instance, NULL);
        } else if (data instanceof ModalMessageWithOptionSelectionData) {
            Logger.debug(`[PopupManager::show] Showing ModalMessageWithOptionSelectionData Popup`);
            ShowMethod.inflate(this.ModalMessageWithOptionSelectionPopupViewModel).invoke(this.Info, data.instance, NULL);
        } else if (data instanceof ModalMessageData) {
            Logger.debug(`[PopupManager::show] Showing ModalMessageData Popup`);
            ShowMethod.inflate(this.ModalMessagePopupViewModel).invoke(this.Info, data.instance, NULL);
        }

        this.waitingForScaling = false;

        // There's was some commented stuff about scaling, but it's removed (see commit d08ea23)
    }

    private static get PopupManagerInstance(): Il2Cpp.Object | undefined {
        if (!this._popupManagerInstance) {
            this._popupManagerInstance = UnityUtils.getInstance(this.PopupManager);
        }
        return this._popupManagerInstance;
    }

    private static get Info(): Il2Cpp.ValueType {
        if (!this._info) {
            this._info = this.PopupInteractionType.field<Il2Cpp.ValueType>("Info").value;
        }
        return this._info;
    }
}
