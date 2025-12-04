import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { Logger } from "../../logger/logger.js";
import { UnityUtils } from "../../utils/unityUtils.js";
import { ModalMessageData } from "./data/ModalMessageData.js";
import { ModalMessageWithOptionSelectionData } from "./data/ModalMessageWithOptionSelectionData.js";

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
        this.ModalMessageWithOptionSelectionPopupViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithOptionSelectionPopupViewModel");

        this.PopupInteractionType = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupInteractionType");

        this.DOScale = this.ShortcutExtensions.method("DOScale", 3);
        this.initHooks();
        Logger.info(`[${this.tag}::init] Initialized`);
    }

    private static initHooks(): void {
        const module = this;

        //@ts-ignore
        this.DOScale.implementation = function (transform: Il2Cpp.Object, endValueVector3: Il2Cpp.ValueType, duration: number) {
            Logger.hook("DOScale called with args:", transform, endValueVector3, duration);
            if (module.waitingForScaling) {
                Logger.debug("Scaling something popup");
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

    public static show(ModalMessageWithOptionSelectionData: ModalMessageWithOptionSelectionData, scale?: number): void;

    // TODO: instance have ActivePopup, I can scale it if Show return true
    public static show(data: ModalMessageData | ModalMessageWithOptionSelectionData, scale?: number): void {
        const Show = this.PopupManagerInstance!.method<boolean>("Show", 3).overload(
            "FGClient.UI.PopupInteractionType",
            "FGClient.UI.ModalMessageBaseData",
            "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
        );

        if (scale) {
            this.waitingForScaling = true;
            this.scale = scale;
        }

        if (data instanceof ModalMessageWithOptionSelectionData) {
            Logger.debug(`[${this.tag}::show] Showing ModalMessageWithOptionSelectionData Popup`);
            Show.inflate(this.ModalMessageWithOptionSelectionPopupViewModel).invoke(this.Info, data.instance, NULL);
        } else if (data instanceof ModalMessageData) {
            Logger.debug(`[${this.tag}::show] Showing ModalMessageData Popup`);
            Show.inflate(this.ModalMessagePopupViewModel).invoke(this.Info, data.instance, NULL);
        }

        this.waitingForScaling = false;

        // const viewModelComponent = this.PopupManagerInstance!.method<Il2Cpp.Object>("get_ActivePopup").invoke();
        // const OnTweenComponent = UnityUtils.getComponentFromObject(viewModelComponent, this.TweenOnPopup);
        // UnityUtils.setEnabledComponent(OnTweenComponent!, false);
        // // const modalObject = UnityUtils.getGameObject(viewModelComponent);
        // const vector3 = UnityUtils.createVector3(scale, scale, scale)
        // UnityUtils.setLocalScale(UnityUtils.getTransform(viewModelComponent), vector3);
    }
}
