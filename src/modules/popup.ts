import { AssemblyHelper } from "../core/assemblyHelper.js";
import { BaseModule } from "../core/baseModule.js";
import { I18n } from "../i18n/i18n.js";
import { Logger } from "../utils/logger.js";

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

export class PopupModule extends BaseModule {
    public name = "popupModule";

    // Classes
    private PopupManager!: Il2Cpp.Class;
    private _popupManagerInstance!: Il2Cpp.Object;
    private ModalMessageData!: Il2Cpp.Class;

    // Enums
    private PopupInteractionType!: Il2Cpp.Class;
    private LocaliseOption!: Il2Cpp.Class;
    private ModalType!: Il2Cpp.Class;
    private OkButtonType!: Il2Cpp.Class;

    private _notLocalised!: Il2Cpp.ValueType;
    private _info!: Il2Cpp.ValueType;

    // Methods
    private ShowModalMessageData!: Il2Cpp.Method;

    public init(): void {
        this.PopupManager = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupManager");
        this.ModalMessageData = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageData");

        this.PopupInteractionType = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupInteractionType");
        this.LocaliseOption = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/LocaliseOption");
        this.ModalType = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/ModalType");
        this.OkButtonType = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/OKButtonType");

        this.ShowModalMessageData = this.PopupManager.method("Show", 3).overload(
            "FGClient.UI.PopupInteractionType",
            "FGClient.UI.ModalMessageData",
            "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
        );
        this.onEnable();
    }

    public override onEnable(): void {
        const module = this;

        //@ts-ignore
        this.ShowModalMessageData.implementation = function (popupInteractionTypeArg, ModalMessageDataArg: Il2Cpp.Object, ModalMessageFailedToShow) {
            Logger.hook("Show called with args:", popupInteractionTypeArg, ModalMessageDataArg, ModalMessageFailedToShow);

            if (ModalMessageDataArg.field<Il2Cpp.String>("Title").value.content == "anticheat_error_title") {
                const NotLocalisedVal = module.NotLocalised;

                ModalMessageDataArg.field<Il2Cpp.ValueType>("LocaliseTitle").value = NotLocalisedVal;
                ModalMessageDataArg.field<Il2Cpp.ValueType>("LocaliseMessage").value = NotLocalisedVal;
                ModalMessageDataArg.field<Il2Cpp.ValueType>("ModalType").value = module.ModalType.field<Il2Cpp.ValueType>(ModalType_enum.MT_OK).value;
                ModalMessageDataArg.field<Il2Cpp.ValueType>("OkButtonType").value = module.OkButtonType.field<Il2Cpp.ValueType>(OkButtonType_enum.Green).value;
                ModalMessageDataArg.field<Il2Cpp.String>("Title").value = Il2Cpp.string(I18n.t("messages.account_banned"));
                ModalMessageDataArg.field<Il2Cpp.String>("Message").value = Il2Cpp.string(I18n.t("messages.account_banned_desc"));
            }

            // this - Instance, so we need overload here
            return this.method("Show", 3)
                .overload("FGClient.UI.PopupInteractionType", "FGClient.UI.ModalMessageData", "FGClient.UI.UIModalMessage.ModalMessageFailedToShow")
                .invoke(popupInteractionTypeArg, ModalMessageDataArg, ModalMessageFailedToShow);
        };
    }

    public showPopup(Title: string, Message: string, ModalTypeValue: ModalType_enum, OkButtonTypeValue: OkButtonType_enum): void {
        try {
            Logger.debug("Showing popup...");
            const ShowModalMessageDataInstance = this.PopupManagerInstance.method<boolean>("Show", 3).overload(
                "FGClient.UI.PopupInteractionType",
                "FGClient.UI.ModalMessageData",
                "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
            );

            // 2 arg
            // Create new instance of ModalMessageData class. Btw, you can't create it in one line, it will return undefined (uhh?)
            const newModalMessageData = this.ModalMessageData.alloc();
            newModalMessageData.method<Il2Cpp.Object>(".ctor").invoke();

            newModalMessageData.field<Il2Cpp.ValueType>("LocaliseTitle").value = this.NotLocalised;
            newModalMessageData.field<Il2Cpp.ValueType>("LocaliseMessage").value = this.NotLocalised;
            newModalMessageData.field<Il2Cpp.ValueType>("ModalType").value = this.ModalType.field<Il2Cpp.ValueType>(ModalTypeValue).value;
            newModalMessageData.field<Il2Cpp.ValueType>("OkButtonType").value = this.OkButtonType.field<Il2Cpp.ValueType>(OkButtonTypeValue).value;
            newModalMessageData.field<Il2Cpp.String>("Title").value = Il2Cpp.string(Title);
            newModalMessageData.field<Il2Cpp.String>("Message").value = Il2Cpp.string(Message);
            newModalMessageData.field("OnCloseButtonPressed").value = NULL;

            // 3 arg is onFailedCallback delegate, which is default is null
            ShowModalMessageDataInstance.invoke(this.Info, newModalMessageData, NULL);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    private get PopupManagerInstance(): Il2Cpp.Object {
        if (!this._popupManagerInstance) {
            this._popupManagerInstance = this.PopupManager.method<Il2Cpp.Object>("get_Instance").invoke();
        }
        return this._popupManagerInstance;
    }

    private get NotLocalised(): Il2Cpp.ValueType {
        if (!this._notLocalised) {
            this._notLocalised = this.LocaliseOption.field<Il2Cpp.ValueType>("NotLocalised").value;
        }
        return this._notLocalised;
    }

    private get Info(): Il2Cpp.ValueType {
        if (!this._info) {
            this._info = this.PopupInteractionType.field<Il2Cpp.ValueType>("Info").value;
        }
        return this._info;
    }
}
