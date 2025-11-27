import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { Logger } from "../logger/logger.js";
import { UnityUtils } from "../utils/unityUtils.js";

export enum ModalType_enum {
    MT_OK = "MT_OK",
    MT_OK_CANCEL = "MT_OK_CANCEL",
    MT_BLOCKING = "MT_BLOCKING",
    MT_WAIT_FOR_EVENT = "MT_WAIT_FOR_EVENT",
    MT_NO_BUTTONS = "MT_NO_BUTTONS"
}

export enum OkButtonType_enum {
    Blue = "Default",
    Red = "Disruptive",
    Green = "Positive",
    Yellow = "CallToAction"
}

export class PopupManagerModule extends BaseModule {
    public name = "PopupManager Manager";

    // Classes and Instances
    private PopupManager!: Il2Cpp.Class;
    private _popupManagerInstance?: Il2Cpp.Object;
    private ModalMessageData!: Il2Cpp.Class;

    // Enums
    private PopupInteractionType!: Il2Cpp.Class;
    private LocaliseOption!: Il2Cpp.Class;
    private ModalType!: Il2Cpp.Class;
    private OkButtonType!: Il2Cpp.Class;

    private _notLocalised!: Il2Cpp.ValueType;
    private _info!: Il2Cpp.ValueType;

    public init(): void {
        this.PopupManager = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupManager");
        this.ModalMessageData = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageData");

        this.PopupInteractionType = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupInteractionType");
        this.LocaliseOption = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/LocaliseOption");
        this.ModalType = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/ModalType");
        this.OkButtonType = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/OKButtonType");
    }

    public showPopup(title: string, message: string, modalType: ModalType_enum, okButtonType: OkButtonType_enum): void {
        try {
            Logger.info("Showing popup:", title, message, modalType, okButtonType);
            const ShowModalMessageDataInstance = this.popupManagerInstance!.method<boolean>("Show", 3).overload(
                "FGClient.UI.PopupInteractionType",
                "FGClient.UI.ModalMessageData",
                "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
            );

            // 2 arg
            const newModalMessageData = this.ModalMessageData.alloc();
            newModalMessageData.method(".ctor").invoke();

            newModalMessageData.field<Il2Cpp.ValueType>("LocaliseTitle").value = this.notLocalised;
            newModalMessageData.field<Il2Cpp.ValueType>("LocaliseMessage").value = this.notLocalised;
            newModalMessageData.field<Il2Cpp.ValueType>("ModalType").value = this.ModalType.field<Il2Cpp.ValueType>(modalType).value;
            newModalMessageData.field<Il2Cpp.ValueType>("OkButtonType").value = this.OkButtonType.field<Il2Cpp.ValueType>(okButtonType).value;
            newModalMessageData.field<Il2Cpp.String>("Title").value = Il2Cpp.string(title);
            newModalMessageData.field<Il2Cpp.String>("Message").value = Il2Cpp.string(message);
            newModalMessageData.field("OnCloseButtonPressed").value = NULL;

            // 3 arg is onFailedCallback delegate, which is default is null
            ShowModalMessageDataInstance.invoke(this.info, newModalMessageData, NULL);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    private get popupManagerInstance(): Il2Cpp.Object | undefined {
        if (!this._popupManagerInstance) {
            this._popupManagerInstance = UnityUtils.getInstance(this.PopupManager);
        }
        return this._popupManagerInstance;
    }

    private get notLocalised(): Il2Cpp.ValueType {
        if (!this._notLocalised) {
            this._notLocalised = this.LocaliseOption.field<Il2Cpp.ValueType>("NotLocalised").value;
        }
        return this._notLocalised;
    }

    private get info(): Il2Cpp.ValueType {
        if (!this._info) {
            this._info = this.PopupInteractionType.field<Il2Cpp.ValueType>("Info").value;
        }
        return this._info;
    }
}
