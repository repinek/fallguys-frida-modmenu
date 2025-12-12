import { AssemblyHelper } from "../../core/AssemblyHelper";
import { Logger } from "../../logger/Logger";
import { UnityUtils } from "../../utils/UnityUtils";
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
 *
 * Inspired a little by gene brawl sources
 */

export class PopupManager {
    public static readonly tag = "PopupManager";

    // Classes
    private static PopupManager: Il2Cpp.Class;
    private static _popupManagerInstance?: Il2Cpp.Object;
    private static ShortcutExtensions: Il2Cpp.Class;

    private static ModalMessagePopupViewModel: Il2Cpp.Class;
    private static ModalMessageWithInputFieldViewModel: Il2Cpp.Class;
    private static ModalMessageWithOptionSelectionPopupViewModel: Il2Cpp.Class;

    // Enums
    private static PopupInteractionType: Il2Cpp.Class;
    private static _info: Il2Cpp.ValueType;

    // Methods
    private static DOScale: Il2Cpp.Method;

    private static waitingForScaling = false;
    private static scale: number;

    public static init(): void {
        this.PopupManager = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupManager");
        this.ShortcutExtensions = AssemblyHelper.DOTween.class("DG.Tweening.ShortcutExtensions");

        this.ModalMessagePopupViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessagePopupViewModel");
        this.ModalMessageWithInputFieldViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithInputFieldViewModel");
        this.ModalMessageWithOptionSelectionPopupViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithOptionSelectionPopupViewModel");

        this.PopupInteractionType = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupInteractionType");

        this.DOScale = this.ShortcutExtensions.method("DOScale", 3);
        this.initHooks();
        Logger.info(`[${this.tag}::init] Initialized`);
    }

    private static initHooks(): void {
        const module = this;

        //@ts-ignore
        // It's a bad implementation, but idk. Not always working!
        this.DOScale.implementation = function (transform: Il2Cpp.Object, endValueVector3: Il2Cpp.ValueType, duration: number) {
            Logger.hook("DOScale called with args:", transform, endValueVector3, duration);
            if (module.waitingForScaling) {
                const scale = module.scale;
                endValueVector3 = UnityUtils.createVector3(scale, scale, scale);
            }

            return this.method("DOScale", 3).invoke(transform, endValueVector3, duration);
        };
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

    public static show(ModalMessageData: ModalMessageData, scale?: number): void;

    public static show(ModalMessageWithInputFieldData: ModalMessageWithInputFieldData, scale?: number): void;

    public static show(ModalMessageWithOptionSelectionData: ModalMessageWithOptionSelectionData, scale?: number): void;

    /**
     * Shows in-game Popup (Modal Message)
     *
     * @param data Configuration object containing Title, Message, Buttons, etc. (use .create() to make one)
     * @param scale (Optional) Custom size of popup
     */
    public static show(data: ModalMessageData | ModalMessageWithInputFieldData | ModalMessageWithOptionSelectionData, scale?: number): void {
        const Show = this.PopupManagerInstance!.method<boolean>("Show", 3).overload(
            "FGClient.UI.PopupInteractionType",
            "FGClient.UI.ModalMessageBaseData",
            "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
        );

        if (scale) {
            this.waitingForScaling = true;
            this.scale = scale;
        }

        if (data instanceof ModalMessageWithInputFieldData) {
            Logger.debug(`[${this.tag}::show] Showing ModalMessageWithInputFieldData Popup`);
            Show.inflate(this.ModalMessageWithInputFieldViewModel).invoke(this.Info, data.instance, NULL);
        } else if (data instanceof ModalMessageWithOptionSelectionData) {
            Logger.debug(`[${this.tag}::show] Showing ModalMessageWithOptionSelectionData Popup`);
            Show.inflate(this.ModalMessageWithOptionSelectionPopupViewModel).invoke(this.Info, data.instance, NULL);
        } else if (data instanceof ModalMessageData) {
            Logger.debug(`[${this.tag}::show] Showing ModalMessageData Popup`);
            Show.inflate(this.ModalMessagePopupViewModel).invoke(this.Info, data.instance, NULL);
        }

        this.waitingForScaling = false;

        // There's was some commented stuff about scaling, but it's removed (see commit d08ea23)
    }
}
