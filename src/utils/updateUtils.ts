import { ModuleManager } from "../core/moduleManager.js";
import { Constants } from "../data/constants.js";
import { ModPreferences } from "../data/modPreferences.js";
import { I18n } from "../i18n/i18n.js";
import { Logger } from "../logger/logger.js";
import { ModalType_enum, OkButtonType_enum, PopupManagerModule } from "../modules/visuals/popupManager.js";
import * as JavaUtils from "./javaUtils.js";
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

// TODO: add logs
export class UpdateUtils {
    // 0 - can't be fetched, 1 - up to date, 2 - outdated
    // TODO: add func to get localised string from state yes i can do it
    static updateState = 0;

    private static modMenuVersion: IModMenuVersion | null = null;

    static checkForUpdate(): void {
        // if (ModPreferences.ENV !== "release") {
        //     Logger.debug("Skipping mod menu version check in dev/staging");
        //     return;
        // }

        JavaUtils.httpGet(Constants.MOD_MENU_VERSION_URL, response => {
            if (!response) {
                Logger.warn("Actual mod menu version can't be fetched");
                return;
            }

            this.modMenuVersion = JSON.parse(response) as IModMenuVersion;

            if (this.modMenuVersion.scriptVersion == ModPreferences.VERSION) {
                this.updateState = 1;
                Logger.info("Mod menu is up to date");
            } else {
                this.updateState = 2;
                Logger.warn("Mod menu version is outdated");
            }
        });
    }

    // Called in CMSLoader::Awake
    static showUpdatePopup(): void {
        const popupManager = ModuleManager.get(PopupManagerModule);
        const scriptVersion = this.modMenuVersion?.scriptVersion;
        if (!scriptVersion) {
            return;
        }
        this.getChangelog(scriptVersion, entry => {
            const date = entry ? entry.date : I18n.t("changelog.unknown_date");
            const text = entry ? entry.changelog : I18n.t("changelog.not_found");

            const title = I18n.t("popups.update.title");
            const message = I18n.t("popups.update.message", scriptVersion, date, text);
            const onClose = Il2Cpp.delegate(UnityUtils.SystemActionBool, (pressed: boolean) => {
                if (pressed) JavaUtils.openURL(Constants.GITHUB_RELEASES_URL);
            });

            const okText = I18n.t("changelog.download");

            popupManager?.showPopup(title, message, ModalType_enum.MT_OK_CANCEL, OkButtonType_enum.Yellow, onClose, okText);
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
