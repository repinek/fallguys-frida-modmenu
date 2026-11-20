import { System } from "../../engine/System";
import { LocaliseOption } from "../../fallguys/wrappers/ui/data/ModalMessageBaseData";
import { ModalMessageData, ModalType, OkButtonType } from "../../fallguys/wrappers/ui/data/ModalMessageData";
import { ModalMessageWithInputFieldData } from "../../fallguys/wrappers/ui/data/ModalMessageWithInputFieldData";
import { ModalMessageWithOptionSelectionData } from "../../fallguys/wrappers/ui/data/ModalMessageWithOptionSelectionData";
import { PopupManager } from "../../fallguys/wrappers/ui/PopupManager";
import { Logger } from "../../utils/Logger";
import { ModPreferences } from "../data/ModPreferences";
import { Catapult } from "../features/Catapult";
import { UpdateChecker } from "../features/UpdateChecker";
import { I18n } from "../i18n/I18n";

export class MenuPopups {
    static showDebugPopup(): void {
        /// #if DEV
        // you can grab logic from here
        const data = ModalMessageData.create();
        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = "Switchgear";
        data.Message =
            "Вы используете крякнутую версию мода. Вы не уважаете мои трусы и старания которые я приложил чтобы создать этот мод. В качестве наказания мод потратил все ваши шмяксы и изменил ваш ник. Ваш аккаунт зарепорчен.";

        data.ModalType = ModalType.MT_OK_CANCEL;
        data.OkButtonType = OkButtonType.Red;

        data.OkTextOverrideId = "OK";
        data.CancelTextOverrideId = "Нет, спасибо";

        data.OnCloseButtonPressed = Il2Cpp.delegate(System.ActionBool, (pressed: boolean) => {
            Logger.debug(`pressed: ${pressed}`);
        });

        PopupManager.show(data, 1.5);
        /// #endif
    }

    static showDebugOptionsPopup(): void {
        /// #if DEV
        // you can grab logic from here
        const data = ModalMessageWithOptionSelectionData.create();
        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = "Selection Popup Test";
        data.Message = "This selection popup created by koluska trost'";

        data.ModalType = ModalType.MT_OK_CANCEL;
        data.OkButtonType = OkButtonType.Yellow;

        data.OkTextOverrideId = "Select language";
        data.CancelTextOverrideId = "DOWNLOAD";

        const stringList = ["hi", "Test", "WheelChair", "Update", "play", "1337"];
        data.OptionStringIds = System.createStringList(stringList);
        data.OnOptionSelectionModalClosed = Il2Cpp.delegate(System.ActionBoolInt, (pressed: boolean, selectedIndex: number) => {
            Logger.debug(`pressed: ${pressed}, selected Index ${selectedIndex}, It's a ${stringList[selectedIndex]}`);
        });
        PopupManager.show(data, 1.5);
        /// #endif
    }

    static showDebugInputPopup(): void {
        /// #if DEV
        // you can grab logic from here
        const data = ModalMessageWithInputFieldData.create();
        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = "Input Popup Test";
        data.Message = 'Debug.log("Bye GD, Hello C#")';

        data.InputText = "koluska";
        data.InputTextPlaceholder = "insert trost'";
        data.RequiredStringLength = 7;
        data.MessageAdditional = "Additional message of input popup";
        data.OnInputFieldModalClosed = Il2Cpp.delegate(System.ActionBoolString, (pressed: boolean, input: Il2Cpp.String) => {
            Logger.debug(`pressed: ${pressed}, input: ${input.content}`);
        });

        PopupManager.show(data, 1.3);
        /// #endif
    }

    static showPlatformPopup(): void {
        const data = ModalMessageWithOptionSelectionData.create();
        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = I18n.t("popups.platform.title");
        data.Message = I18n.t("popups.platform.message");
        data.OkTextOverrideId = I18n.t("popups.platform.ok");

        data.ModalType = ModalType.MT_OK_CANCEL;
        data.OkButtonType = OkButtonType.Green;

        const platforms = Catapult.getLocalisedPlatforms();
        data.OptionStringIds = System.createStringList(platforms);

        data.OnOptionSelectionModalClosed = Il2Cpp.delegate(System.ActionBoolInt, (pressed: boolean, selectedIndex: number) => {
            if (pressed) {
                const selectedPlatform = Catapult.PLATFORMS[selectedIndex];
                Catapult.changePlatform(selectedPlatform);
            }
        });

        PopupManager.show(data, 1.5);
    }

    static showLanguagePopup(): void {
        const data = ModalMessageWithOptionSelectionData.create();
        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = I18n.t("popups.language.title");
        data.Message = I18n.t("popups.language.message");
        data.OkTextOverrideId = I18n.t("popups.language.ok");

        data.ModalType = ModalType.MT_OK_CANCEL;
        data.OkButtonType = OkButtonType.Green;

        const languageNames = I18n.getLocalisedLanguages();
        data.OptionStringIds = System.createStringList(languageNames);

        data.OnOptionSelectionModalClosed = Il2Cpp.delegate(System.ActionBoolInt, (pressed: boolean, selectedIndex: number) => {
            if (pressed) {
                const selectedLocale = I18n.supportedLocales[selectedIndex];
                I18n.changeLocale(selectedLocale);
                Logger.toast(I18n.t("menu.toasts.on_locale_changed", languageNames[selectedIndex]), 0);
            }
        });

        PopupManager.show(data, 1.4);
    }

    static showCreditsPopup(): void {
        const data = ModalMessageData.create();
        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = I18n.t("popups.credits.title");
        data.Message = I18n.t("popups.credits.message");

        data.ModalType = ModalType.MT_OK;
        data.OkButtonType = OkButtonType.Green;

        PopupManager.show(data);
    }

    static showChangelogPopup(): void {
        UpdateChecker.fetchChangelog(ModPreferences.VERSION, entry => {
            const data = ModalMessageData.create();

            const date = entry ? entry.date : I18n.t("update_utils.unknown_date");
            const changelog = entry ? entry.changelog : I18n.t("update_utils.not_found");

            data.LocaliseOption = LocaliseOption.NotLocalised;
            data.Title = I18n.t("popups.changelog.title", ModPreferences.VERSION, date);
            data.Message = I18n.t("popups.changelog.message", changelog);

            data.ModalType = ModalType.MT_OK;
            data.OkButtonType = OkButtonType.Green;

            PopupManager.show(data);
        });
    }
}
