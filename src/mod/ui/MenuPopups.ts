import { AndroidUtils } from "../../android/AndroidUtils";
import { System } from "../../engine/System";
import { LocaliseOption } from "../../fallguys/wrappers/FGClient/UI/data/ModalMessageBaseData";
import { ModalMessageData, ModalType, OkButtonType } from "../../fallguys/wrappers/FGClient/UI/data/ModalMessageData";
import { ModalMessageWithOptionSelectionData } from "../../fallguys/wrappers/FGClient/UI/data/ModalMessageWithOptionSelectionData";
import { PopupManager } from "../../fallguys/wrappers/FGClient/UI/PopupManager";
import { Logger } from "../../utils/Logger";
import { Constants } from "../data/Constants";
import { ModPreferences } from "../data/ModPreferences";
import { CatapultSpoof } from "../features/network/Catapult";
import { I18n } from "../i18n/I18n";
import { ChangelogEntry } from "../utils/UpdateChecker";

/**
 * All in-game popups lives here
 *
 * Only popup logic here
 */
export class MenuPopups {
    static showPlatformPopup(): void {
        const data = ModalMessageWithOptionSelectionData.create();
        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = I18n.t("popups.platform.title");
        data.Message = I18n.t("popups.platform.message");
        data.OkTextOverrideId = I18n.t("popups.platform.ok");

        data.ModalType = ModalType.MT_OK_CANCEL;
        data.OkButtonType = OkButtonType.Green;

        const platforms = CatapultSpoof.PLATFORMS;
        const labels = platforms.map(platform => I18n.t(`platforms.${platform}`));
        data.OptionStringIds = System.createStringList(labels);

        data.OnOptionSelectionModalClosed = Il2Cpp.delegate(System.ActionBoolInt, (pressed: boolean, selectedIndex: number) => {
            if (pressed) {
                const selectedPlatform = platforms[selectedIndex];
                CatapultSpoof.platformPreference.save(selectedPlatform);
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
                const selectedLocale = I18n.supportedLanguages[selectedIndex];
                I18n.languagePreference.save(selectedLocale);
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

    static showBannedPopup(): void {
        const data = ModalMessageData.create();
        data.Title = I18n.t("popups.ban_bypass.title");
        data.Message = I18n.t("popups.ban_bypass.message");
        data.ModalType = ModalType.MT_OK;
        data.OkButtonType = OkButtonType.Green;

        PopupManager.show(data);
    }

    static showChangelogPopup(changelogEntry: ChangelogEntry | undefined): void {
        const data = ModalMessageData.create();

        const date = changelogEntry ? changelogEntry.date : I18n.t("update_utils.unknown_date");
        const changelog = changelogEntry ? changelogEntry.changelog : I18n.t("update_utils.not_found");

        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = I18n.t("popups.changelog.title", ModPreferences.VERSION, date);
        data.Message = I18n.t("popups.changelog.message", changelog);

        data.ModalType = ModalType.MT_OK;
        data.OkButtonType = OkButtonType.Green;

        PopupManager.show(data);
    }

    static showUpdatePopup(version: string, changelogEntry: ChangelogEntry | undefined): void {
        const data = ModalMessageData.create();

        const date = changelogEntry ? changelogEntry.date : I18n.t("update_utils.unknown_date");
        const changelog = changelogEntry ? changelogEntry.changelog : I18n.t("update_utils.not_found");

        data.LocaliseOption = LocaliseOption.NotLocalised;
        data.Title = I18n.t("popups.update.title");
        data.Message = I18n.t("popups.update.message", version, date, changelog);
        data.OkTextOverrideId = I18n.t("popups.update.ok");

        data.ModalType = ModalType.MT_OK_CANCEL;
        data.OkButtonType = OkButtonType.Yellow;

        data.OnCloseButtonPressed = Il2Cpp.delegate(System.ActionBool, (pressed: boolean) => {
            if (pressed) AndroidUtils.openURL(Constants.GITHUB_RELEASES_URL);
        });

        data.ShowExternalLinkIcon = true;

        PopupManager.show(data);
    }
}
