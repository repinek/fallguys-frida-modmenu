import { AssemblyHelper } from "../../../core/assemblyHelper.js";
import { ModalMessageBaseData } from "./ModalMessageBaseData.js";
import { UnityUtils } from "../../../utils/unityUtils.js";

export enum ModalType {
    MT_OK = "MT_OK",
    MT_OK_CANCEL = "MT_OK_CANCEL",
    MT_BLOCKING = "MT_BLOCKING",
    MT_WAIT_FOR_EVENT = "MT_WAIT_FOR_EVENT",
    MT_NO_BUTTONS = "MT_NO_BUTTONS"
}

export enum OkButtonType {
    Blue = "Default",
    Red = "Disruptive",
    Green = "Positive",
    Yellow = "CallToAction"
}

/** Wrapper over FGClient::UI::ModalMessageData */
export class ModalMessageData extends ModalMessageBaseData {
    private static _class: Il2Cpp.Class;

    static get Class(): Il2Cpp.Class {
        if (!this._class) {
            this._class = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageData");
        }
        return this._class;
    }

    static create(): ModalMessageData {
        const instance = UnityUtils.createInstance(this.Class);
        return new ModalMessageData(instance);
    }

    set ModalType(type: ModalType) {
        const enumClass = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/ModalType");
        this.instance.field("ModalType").value = enumClass.field(type).value;
    }

    set OkButtonType(type: OkButtonType) {
        const enumClass = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/OKButtonType");
        this.instance.field("OkButtonType").value = enumClass.field(type).value;
    }

    /**
     * delegate _onCloseButtonPressed(bool wasOk);
     *
     * @param callback Il2Cpp.delegate with System::Action infalted by System::Boolean
     */
    set OnCloseButtonPressed(callback: Il2Cpp.Object) {
        this.instance.field("OnCloseButtonPressed").value = callback;
    }

    set ShowExternalLinkIcon(value: boolean) {
        this.instance.field("ShowExternalLinkIcon").value = value;
    }
}
