import { Constants } from "../data/constants.js";
import { ModPreferences } from "../data/modPreferences.js";
import { I18n } from "../i18n/i18n.js";
import { Logger } from "../logger/logger.js";
import { LocaliseOption } from "../ui/popup/data/ModalMessageBaseData.js";
import { ModalType, OkButtonType, ModalMessageData } from "../ui/popup/data/ModalMessageData.js";
import { PopupManager } from "../ui/popup/popupManager.js";
import { JavaUtils } from "./javaUtils.js";
import { UnityUtils } from "./unityUtils.js";

interface IModMenuVersion {
    scriptVersion: string;
    forGameVersion: string;
}

interface IChangelogEntry {
    scriptVersion: string;
    date: string;
    changelog: string;
}

export class UpdateUtils {
    private static readonly tag = "UpdateUtils";

    private static modMenuUpdateVersion: IModMenuVersion | null = null;

    static checkForUpdate(): void {
        if (ModPreferences.ENV !== "release") {
            Logger.debug(`[${this.tag}::checkForUpdate] Skipping mod menu version check in dev/staging`);
            return;
        }

        JavaUtils.httpGet(Constants.MOD_MENU_VERSION_URL, response => {
            if (!response) {
                Logger.warn(`[${this.tag}::checkForUpdate] Actual mod menu version can't be fetched`);
                return;
            }

            this.modMenuUpdateVersion = JSON.parse(response) as IModMenuVersion;

            if (this.modMenuUpdateVersion.scriptVersion == ModPreferences.VERSION) {
                Logger.info(`[${this.tag}::checkForUpdate] Mod menu is up to date`);
            } else {
                Logger.warn(`[${this.tag}::checkForUpdate] Mod menu version is outdated`);
                this.showUpdatePopup();
            }
        });
    }

    private static showUpdatePopup(): void {
        if (!this.modMenuUpdateVersion) {
            return;
        }

        const scriptVersion = this.modMenuUpdateVersion.scriptVersion;

        this.getChangelog(scriptVersion, entry => {
            const data = ModalMessageData.create();

            const date = entry ? entry.date : I18n.t("update_utils.unknown_date");
            const changelog = entry ? entry.changelog : I18n.t("update_utils.not_found");

            data.LocaliseOption = LocaliseOption.NotLocalised;
            data.Title = I18n.t("popups.update.title");
            data.Message = I18n.t("popups.update.message", scriptVersion, date, changelog);
            data.OkTextOverrideId = I18n.t("popups.update.ok");

            data.ModalType = ModalType.MT_OK_CANCEL;
            data.OkButtonType = OkButtonType.Yellow;

            data.OnCloseButtonPressed = Il2Cpp.delegate(UnityUtils.SystemActionBool, (pressed: boolean) => {
                if (pressed) JavaUtils.openURL(Constants.GITHUB_RELEASES_URL);
            });

            data.ShowExternalLinkIcon = true;

            PopupManager.show(data);
        });
    }

    // TODO: the same as httpGet
    // TODO: add link to apk too in changelog
    static getChangelog(targetScriptVersion: string, onReceive: (entry: IChangelogEntry | null) => void): void {
        JavaUtils.httpGet(Constants.MOD_MENU_CHANGELOG_URL, response => {
            if (!response) {
                onReceive(null);
                return;
            }

            const history = JSON.parse(response) as IChangelogEntry[];

            const entry = history.find(e => e.scriptVersion === targetScriptVersion);

            if (entry) onReceive(entry);
            else onReceive(null);
        });
    }
}
