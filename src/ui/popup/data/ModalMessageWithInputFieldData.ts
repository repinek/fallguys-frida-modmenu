import { AssemblyHelper } from "../../../core/AssemblyHelper";
import { ModalMessageData } from "./ModalMessageData";
import { UnityUtils } from "../../../utils/UnityUtils";

/*
 * There's also enums
 * public FontStyles InputFieldFontStyles = FontStyles.Bold;
 * public TMP_InputField.ContentType InputFieldType = TMP_InputField.ContentType.Standard;
 *
 * but I'm too lazy & It's useless to implement
 */

/** Wrapper over FGClient.UI.ModalMessageWithInputFieldData */
export class ModalMessageWithInputFieldData extends ModalMessageData {
    private static _inputClass: Il2Cpp.Class;

    static override get Class(): Il2Cpp.Class {
        if (!this._inputClass) {
            this._inputClass = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithInputFieldData");
        }
        return this._inputClass;
    }

    static override create(): ModalMessageWithInputFieldData {
        const instance = UnityUtils.createInstance(this.Class);
        return new ModalMessageWithInputFieldData(instance);
    }

    set InputText(value: string) {
        this.instance.field("InputText").value = Il2Cpp.string(value);
    }

    set InputTextPlaceholder(value: string) {
        this.instance.field("InputTextPlaceholder").value = Il2Cpp.string(value);
    }

    set RequiredStringLength(value: number) {
        this.instance.field("RequiredStringLength").value = value;
    }

    set MessageAdditional(value: string) {
        this.instance.field("MessageAdditional").value = Il2Cpp.string(value);
    }

    /**
     * delegate ModalMessageClosedDelegate(bool wasOk, string input);
     *
     * @param callback Il2Cpp.delegate with System::Action infalted by System::Boolean and System::String
     */
    set OnInputFieldModalClosed(callback: Il2Cpp.Object) {
        this.instance.field("OnInputFieldModalClosed").value = callback;
    }

    set TrimSpacesOnClose(value: boolean) {
        this.instance.field("TrimSpacesOnClose").value = value;
    }
}
