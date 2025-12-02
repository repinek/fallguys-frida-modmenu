import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";
import { Logger } from "../../logger/logger.js";
// import { GameLocalization } from "../../utils/game/gameLocalization.js";
import { UnityUtils } from "../../utils/unityUtils.js";

// TODO: fix this

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
    public readonly name = "PopupManager";

    // Classes and Instances
    private PopupManager!: Il2Cpp.Class;
    private _popupManagerInstance?: Il2Cpp.Object;
    private ModalMessageData!: Il2Cpp.Class;
    private ModalMessageWithOptionSelectionData!: Il2Cpp.Class;

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
        this.ModalMessageWithOptionSelectionData = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithOptionSelectionData");

        this.PopupInteractionType = AssemblyHelper.MTFGClient.class("FGClient.UI.PopupInteractionType");
        this.LocaliseOption = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/LocaliseOption");
        this.ModalType = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/ModalType");
        this.OkButtonType = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/OKButtonType");
    }

    // TODO: add custom size
    // TODO: too many args, do smth with that
    public showPopup(
        title: string,
        message: string,
        modalType: ModalType_enum,
        okButtonType: OkButtonType_enum,
        onCloseButtonPressed: Il2Cpp.Object | NativePointer = NULL,
        okTextOverride: string | null = null,
        cancelTextOverride: string | null = null
    ): void {
        try {
            Logger.info("Showing popup");
            const ShowModalMessageDataInstance = this.popupManagerInstance!.method<boolean>("Show", 3).overload(
                "FGClient.UI.PopupInteractionType",
                "FGClient.UI.ModalMessageData",
                "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
            );

            // 2 arg
            const newModalMessageData = UnityUtils.createInstance(this.ModalMessageData);

            newModalMessageData.field<Il2Cpp.ValueType>("LocaliseTitle").value = this.notLocalised;
            newModalMessageData.field<Il2Cpp.ValueType>("LocaliseMessage").value = this.notLocalised;
            newModalMessageData.field<Il2Cpp.ValueType>("ModalType").value = this.ModalType.field<Il2Cpp.ValueType>(modalType).value;
            newModalMessageData.field<Il2Cpp.ValueType>("OkButtonType").value = this.OkButtonType.field<Il2Cpp.ValueType>(okButtonType).value;
            newModalMessageData.field<Il2Cpp.String>("Title").value = Il2Cpp.string(title);
            newModalMessageData.field<Il2Cpp.String>("Message").value = Il2Cpp.string(message);
            newModalMessageData.field("OnCloseButtonPressed").value = onCloseButtonPressed;
            if (okTextOverride) {
                // const okTextId = GameLocalization.getOrCreateKey(okTextOverride);
                newModalMessageData.field<Il2Cpp.String>("OkTextOverrideId").value = Il2Cpp.string(okTextOverride);
            }
            if (cancelTextOverride) {
                // const cancelTextId = GameLocalization.getOrCreateKey(cancelTextOverride);
                newModalMessageData.field<Il2Cpp.String>("CancelTextOverrideId").value = Il2Cpp.string(cancelTextOverride);
            }

            // 3 arg is onFailedCallback delegate, which is default is null
            ShowModalMessageDataInstance.invoke(this.info, newModalMessageData, NULL);
        } catch (error: any) {
            Logger.errorThrow(error);
        }
    }

    public showSelectionOptionPopup(
        title: string,
        message: string,
        options: string[],
        onCloseButtonPressed: Il2Cpp.Object | NativePointer = NULL,
        okTextOverride: string | null = null
    ) {
        Logger.info("Showing popup with selection Option");
        const ShowModalMessageDataInstance = this.popupManagerInstance!.method<boolean>("Show", 3).overload(
            "FGClient.UI.PopupInteractionType",
            "FGClient.UI.ModalMessageWithOptionSelectionData",
            "FGClient.UI.UIModalMessage.ModalMessageFailedToShow"
        );

        const newModalMessageData = UnityUtils.createInstance(this.ModalMessageWithOptionSelectionData);

        newModalMessageData.field<Il2Cpp.ValueType>("LocaliseTitle").value = this.notLocalised;
        newModalMessageData.field<Il2Cpp.ValueType>("LocaliseMessage").value = this.notLocalised;
        newModalMessageData.field<Il2Cpp.String>("Title").value = Il2Cpp.string(title);
        newModalMessageData.field<Il2Cpp.String>("Message").value = Il2Cpp.string(message);
        newModalMessageData.field("OnOptionSelectionModalClosed").value = onCloseButtonPressed;
        if (okTextOverride) {
            // const okTextId = GameLocalization.getOrCreateKey(okTextOverride);
            newModalMessageData.field<Il2Cpp.String>("OkTextOverrideId").value = Il2Cpp.string(okTextOverride);
        }
        // ids in _localisedStrings
        // const StringsIds: string[] = [];

        // for (const string of options) {
        //     const stringKey = GameLocalization.getOrCreateKey(string); // create localisedString
        //     StringsIds.push(stringKey);
        // }

        // // Create list with localised Ids
        const optionsGenericList = UnityUtils.createStringList(options);
        newModalMessageData.field("OptionStringIds").value = optionsGenericList;

        ShowModalMessageDataInstance.invoke(this.info, newModalMessageData, NULL);
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
