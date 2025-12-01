import { AssemblyHelper } from "../../../core/assemblyHelper.js";
import { ModalMessageData } from "./ModalMessageData.js";
import { UnityUtils } from "../../../utils/unityUtils.js";

/** Wrapper over FGClient.UI.ModalMessageWithOptionSelectionData */
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

    set OptionStringIds(list: Il2Cpp.Object) {
        this.instance.field("OptionStringIds").value = list;
    }

    set OnOptionSelectionModalClosed(callback: Il2Cpp.Object) {
        this.instance.field("OnOptionSelectionModalClosed").value = callback;
    }
}
