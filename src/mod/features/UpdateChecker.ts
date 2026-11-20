import { System } from "../../engine/System";
import { UnityUtils } from "../../engine/UnityUtils";
import { UnityWebRequest } from "../../engine/wrappers/UnityWebRequest";
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
    private static latestVersionInfo: IModMenuVersion;

    /** Prints warn if gameVersion != ModPreferences game version */
    static checkVersionCompatibility(): void {
        const gameVersion = Il2Cpp.application.version!;

        if (gameVersion !== ModPreferences.FOR_GAME_VERSION) {
            Logger.warn(
                `[UpdateChecker::checkGameVersion] Game version ${gameVersion} is not supported. Expected ${ModPreferences.FOR_GAME_VERSION}. Things may break`
            );
        }
    }

    static async checkForUpdate(): Promise<void> {
        if (ModPreferences.ENV !== "release") {
            Logger.debug(`[UpdateChecker::checkForUpdate] Skipping mod menu version check in non-release builds`);
            return;
        }

        const updateVersion = await UpdateChecker.fetchJson(Constants.MOD_MENU_VERSION_URL);
        if (updateVersion === undefined) return;

        if (!UpdateChecker.isValidModMenuVersionJson(updateVersion)) {
            Logger.warn(`[UpdateChecker::checkForUpdate] Invalid mod menu version response`);
            return;
        }

        UpdateChecker.latestVersionInfo = updateVersion;
        if (updateVersion.scriptVersion === ModPreferences.VERSION) {
            Logger.info(`[UpdateChecker::checkForUpdate] Mod menu is up to date`);
        } else {
            Logger.warn(`[UpdateChecker::checkForUpdate] Mod menu version is outdated`);
            UpdateChecker.showUpdatePopup();
        }
    }

    private static showUpdatePopup(): void {
        if (!UpdateChecker.latestVersionInfo) {
            return;
        }

        const scriptVersion = UpdateChecker.latestVersionInfo.scriptVersion;

        UpdateChecker.fetchChangelog(scriptVersion, entry => {
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

    // TODO: add link to apk too in changelog
    static async fetchChangelog(targetScriptVersion: string, onReceive: (entry: IChangelogEntry | undefined) => void): Promise<void> {
        const history = await UpdateChecker.fetchJson(Constants.MOD_MENU_CHANGELOG_URL);
        let entry: IChangelogEntry | undefined;
        if (history !== undefined) {
            if (UpdateChecker.isChangelogHistory(history)) {
                entry = history.find(item => item.scriptVersion === targetScriptVersion);
            } else {
                Logger.warn(`[UpdateChecker::getChangelog] Invalid changelog response`);
            }
        }
        await UnityUtils.runInMain(() => {
            try {
                onReceive(entry);
            } catch (error) {
                Logger.error(`[UpdateChecker::getChangelog] ${error}`);
            }
        });
    }

    private static async fetchJson(url: string): Promise<unknown> {
        try {
            const request = await UnityWebRequest.sendGet(url);
            try {
                return JSON.parse(request.text);
            } finally {
                request.dispose();
            }
        } catch (error) {
            Logger.warn(`[UpdateChecker::fetchJson] Failed to load ${url}: ${error}`);
            return undefined;
        }
    }

    private static isValidModMenuVersionJson(value: unknown): value is IModMenuVersion {
        if (!value || typeof value !== "object") return false;

        const version = value as Record<string, unknown>;
        return typeof version.scriptVersion === "string" && version.scriptVersion.trim().length > 0 && typeof version.forGameVersion === "string";
    }

    private static isChangelogHistory(value: unknown): value is IChangelogEntry[] {
        return Array.isArray(value) && value.every(entry => UpdateChecker.isChangelogEntry(entry));
    }

    private static isChangelogEntry(value: unknown): value is IChangelogEntry {
        if (!value || typeof value !== "object") return false;

        const entry = value as Record<string, unknown>;
        return typeof entry.scriptVersion === "string" && typeof entry.date === "string" && typeof entry.changelog === "string";
    }
}
