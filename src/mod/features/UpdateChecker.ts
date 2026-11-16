import { System } from "../../engine/System";
import { LocaliseOption } from "../../fallguys/wrappers/ui/data/ModalMessageBaseData";
import { ModalMessageData, ModalType, OkButtonType } from "../../fallguys/wrappers/ui/data/ModalMessageData";
import { PopupManager } from "../../fallguys/wrappers/ui/PopupManager";
import { JavaUtils } from "../../utils/JavaUtils";
import { Logger } from "../../utils/Logger";
import { Constants } from "../data/Constants";
import { ModPreferences } from "../data/ModPreferences";
import { I18n } from "../i18n/I18n";

interface IModMenuVersion {
    scriptVersion: string;
    forGameVersion: string;
}

interface IChangelogEntry {
    scriptVersion: string;
    date: string;
    changelog: string;
}

export class UpdateChecker {
    private static modMenuUpdateVersion: IModMenuVersion;

    static checkGameVersion(): void {
        const gameVersion = Il2Cpp.application.version!;

        if (gameVersion !== ModPreferences.FOR_GAME_VERSION) {
            Logger.warn(
                `[UpdateChecker::checkGameVersion] Game version ${gameVersion} is not supported. Expected ${ModPreferences.FOR_GAME_VERSION}. Things may break`
            );
        }
    }

    static checkForUpdate(): void {
        if (ModPreferences.ENV !== "release") {
            Logger.debug(`[UpdateChecker::checkForUpdate] Skipping mod menu version check in dev`);
            return;
        }

        JavaUtils.httpGet(Constants.MOD_MENU_VERSION_URL, response => {
            if (!response) {
                Logger.warn(`[UpdateChecker::checkForUpdate] Actual mod menu version can't be fetched`);
                return;
            }

            try {
                const updateVersion = JSON.parse(response) as unknown;

                if (!this.isModMenuVersion(updateVersion)) {
                    Logger.warn(`[UpdateChecker::checkForUpdate] Invalid mod menu version response`);
                    return;
                }

                this.modMenuUpdateVersion = updateVersion;
            } catch {
                Logger.warn(`[UpdateChecker::checkForUpdate] Invalid mod menu version response`);
                return;
            }

            if (this.modMenuUpdateVersion.scriptVersion === ModPreferences.VERSION) {
                Logger.info(`[UpdateChecker::checkForUpdate] Mod menu is up to date`);
            } else {
                Logger.warn(`[UpdateChecker::checkForUpdate] Mod menu version is outdated`);
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

            data.OnCloseButtonPressed = Il2Cpp.delegate(System.ActionBool, (pressed: boolean) => {
                if (pressed) JavaUtils.openURL(Constants.GITHUB_RELEASES_URL);
            });

            data.ShowExternalLinkIcon = true;

            PopupManager.show(data);
        });
    }

    // TODO: the same as httpGet
    // TODO: add link to apk too in changelog
    static getChangelog(targetScriptVersion: string, onReceive: (entry: IChangelogEntry | undefined) => void): void {
        JavaUtils.httpGet(Constants.MOD_MENU_CHANGELOG_URL, response => {
            if (!response) {
                onReceive(undefined);
                return;
            }

            try {
                const history = JSON.parse(response) as unknown;

                if (!this.isChangelogHistory(history)) {
                    Logger.warn(`[UpdateChecker::getChangelog] Invalid changelog response`);
                    onReceive(undefined);
                    return;
                }

                const entry = history.find(e => e.scriptVersion === targetScriptVersion);

                if (entry) onReceive(entry);
                else onReceive(undefined);
            } catch {
                Logger.warn(`[UpdateChecker::getChangelog] Invalid changelog response`);
                onReceive(undefined);
            }
        });
    }

    private static isModMenuVersion(value: unknown): value is IModMenuVersion {
        if (!value || typeof value !== "object") return false;

        const version = value as Record<string, unknown>;
        return typeof version.scriptVersion === "string" && version.scriptVersion.trim().length > 0 && typeof version.forGameVersion === "string";
    }

    private static isChangelogHistory(value: unknown): value is IChangelogEntry[] {
        return Array.isArray(value) && value.every(entry => this.isChangelogEntry(entry));
    }

    private static isChangelogEntry(value: unknown): value is IChangelogEntry {
        if (!value || typeof value !== "object") return false;

        const entry = value as Record<string, unknown>;
        return typeof entry.scriptVersion === "string" && typeof entry.date === "string" && typeof entry.changelog === "string";
    }
}
