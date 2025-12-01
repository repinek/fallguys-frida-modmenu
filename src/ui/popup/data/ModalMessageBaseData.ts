import { AssemblyHelper } from "../../../core/assemblyHelper.js";

export enum LocaliseOption {
    Localised = 0,
    NotLocalised = 1
}

/** Wrapper over FGClient.UI.ModalMessageBaseData */
export abstract class ModalMessageBaseData {
    public instance: Il2Cpp.Object;

    constructor(instance: Il2Cpp.Object) {
        this.instance = instance;
    }

    set Title(value: string) {
        this.instance.field("Title").value = Il2Cpp.string(value);
    }

    set Message(value: string) {
        this.instance.field("Message").value = Il2Cpp.string(value);
    }

    set OkTextOverrideId(value: string) {
        this.instance.field("OkTextOverrideId").value = Il2Cpp.string(value);
    }

    set CancelTextOverrideId(value: string) {
        this.instance.field("CancelTextOverrideId").value = Il2Cpp.string(value);
    }

    set LocaliseOption(value: LocaliseOption) {
        const OptionEnum = AssemblyHelper.MTFGClient.class("FGClient.UI.UIModalMessage/LocaliseOption");

        const fieldName = value === LocaliseOption.NotLocalised ? "NotLocalised" : "Localised";
        const enumValue = OptionEnum.field(fieldName).value;

        this.instance.field("LocaliseTitle").value = enumValue;
        this.instance.field("LocaliseMessage").value = enumValue;
    }
}
