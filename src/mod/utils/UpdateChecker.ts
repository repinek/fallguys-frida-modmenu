import { UnityWebRequest } from "../../engine/wrappers/UnityWebRequest";
import { Logger } from "../../utils/Logger";
import { Constants } from "../data/Constants";
import { ModPreferences } from "../data/ModPreferences";

interface VersionResponse {
    scriptVersion: string;
    forGameVersion: string;
}

export interface ChangelogEntry {
    scriptVersion: string;
    date: string;
    changelog: string;
}

export class UpdateChecker {
    private static _latestVersion: string | null = null;
    private static _latestChangelog: ChangelogEntry | null = null;

    /** Fetches the latest version and its changelog, then caches both */
    static async fetchLatestVersion(): Promise<void> {
        if (ModPreferences.ENV !== "release") {
            Logger.warn("[UpdateChecker::checkVersion] Skipping version check in non-release builds");
            return;
        }

        try {
            const request = await UnityWebRequest.sendGet(Constants.MOD_MENU_VERSION_URL);
            const json = JSON.parse(request.text) as VersionResponse;
            this._latestVersion = json.scriptVersion;
            this._latestChangelog = (await this.getChangelog(json.scriptVersion)) ?? null;
            request.dispose();
            Logger.info(`[UpdateChecker::checkVersion] Fetched the latest script version: ${json.scriptVersion}`);
        } catch (error) {
            Logger.errorThrow(`[UpdateChecker::checkVersion] Failed to fetch the latest version: ${error}`);
        }
    }

    /**
     * Fetches the changelog entry for the specified version
     *
     * @returns The matching entry, or `undefined` if it is unavailable
     */
    static async getChangelog(version: string): Promise<ChangelogEntry | undefined> {
        try {
            const request = await UnityWebRequest.sendGet(Constants.MOD_MENU_CHANGELOG_URL);
            const entries = JSON.parse(request.text) as ChangelogEntry[];
            request.dispose();
            return entries.find(entry => entry?.scriptVersion === version);
        } catch (error) {
            Logger.error(`[UpdateChecker::getChangelog] Failed to fetch the changelog for version ${version}: ${error}`);
            return undefined;
        }
    }

    static get latestVersion(): string | null {
        return this._latestVersion ?? null;
    }

    static get latestChangelog(): ChangelogEntry | null {
        return this._latestChangelog ?? null;
    }
}
