import { AssemblyHelper } from "../../../core/AssemblyHelper";
import { ModalMessageData } from "./ModalMessageData";
import { UnityUtils } from "../../../utils/UnityUtils";

/*
 * There's also
 * public int? OptionTextWidthOverride;
 *
 * but I'm too lazy & It's useless to implement
 */

/** Wrapper over FGClient::UI::ModalMessageWithOptionSelectionData */
export class ModalMessageWithOptionSelectionData extends ModalMessageData {
    private static _selectionClass: Il2Cpp.Class;

    static override get Class(): Il2Cpp.Class {
        if (!this._selectionClass) {
            this._selectionClass = AssemblyHelper.MTFGClient.class("FGClient.UI.ModalMessageWithOptionSelectionData");
        }
        return this._selectionClass;
    }

    static override create(): ModalMessageWithOptionSelectionData {
        const instance = UnityUtils.createInstance(this.Class);
        return new ModalMessageWithOptionSelectionData(instance);
    }

    /** @param list Il2Cpp.Object Genegric::List with Il2Cpp.Strings */
    set OptionStringIds(list: Il2Cpp.Object) {
        this.instance.field("OptionStringIds").value = list;
    }

    /**
     * delegate ModalMessageClosedDelegate(bool wasOk, int selectedIndex);
     *
     * @param callback Il2Cpp.delegate with System::Action infalted by System::Boolean and System::Int32
     */
    set OnOptionSelectionModalClosed(callback: Il2Cpp.Object) {
        this.instance.field("OnOptionSelectionModalClosed").value = callback;
    }
}
