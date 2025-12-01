import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { Logger } from "../../logger/logger.js";
import { UnityUtils } from "../../utils/unityUtils.js";
import { ModalMessageData } from "./data/ModalMessageData.js";
import { ModalMessageWithOptionSelectionData } from "./data/ModalMessageWithOptionSelectionData.js";

/*
 * Wrapper over FGClient.UI.PopupManager
 *
 * Easily extendable to add other popups
 *
 * Inspired a little by gene brawl sources
 */

export class PopupManager {
    public static readonly tag = "PopupManager";

    // Classes
    private static PopupManager: Il2Cpp.Class;
    private static _popupManagerInstance?: Il2Cpp.Object;

    private static ModalMessagePopupViewModel: Il2Cpp.Class;
    private static ModalMessageWithOptionSelectionPopupViewModel: Il2Cpp.Class;

    // Enums
    private static PopupInteractionType: Il2Cpp.Class;
    private static _info: Il2Cpp.ValueType;

    public static init(): void {
        this.PopupManager = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupManager");

        this.ModalMessagePopupViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessagePopupViewModel");
        this.ModalMessageWithOptionSelectionPopupViewModel = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithOptionSelectionPopupViewModel");

        this.PopupInteractionType = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupInteractionType");

        Logger.info(`[${this.tag}::init] Initialized`);
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

    public static show(ModalMessageData: ModalMessageData): void;

    public static show(ModalMessageWithOptionSelectionData: ModalMessageWithOptionSelectionData): void;

    public static show(data: ModalMessageData | ModalMessageWithOptionSelectionData): void {
        const Show = this.PopupManagerInstance!.method("Show", 3).overload(
            "FGClient.UI.PopupInteractionType",
            "FGClient.UI.ModalMessageBaseData",
            "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
        );

        // this guy is still WIP
        if (data instanceof ModalMessageWithOptionSelectionData) {
            Logger.debug(`[${this.tag}::show] Showing ModalMessageWithOptionSelectionData Popup`);
            Show.inflate(this.ModalMessageWithOptionSelectionPopupViewModel).invoke(this.Info, data.instance, NULL);
        } else if (data instanceof ModalMessageData) {
            Logger.debug(`[${this.tag}::show] Showing ModalMessageData Popup`);
            Show.inflate(this.ModalMessagePopupViewModel).invoke(this.Info, data.instance, NULL);
        }
    }
}
