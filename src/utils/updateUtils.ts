import { Constants } from "../data/constants.js";
import { ModPreferences } from "../data/modPreferences.js";
import * as JavaUtils from "./javaUtils.js";
import { Logger } from "../logger/logger.js";

export class UpdateUtils {
    // TODO: just show popup if update is available
    public static checkForUpdate(): void {
        if (ModPreferences.ENV !== "release") {
            Logger.debug("Skipping mod menu version check in dev/staging");
            return;
        }
        JavaUtils.httpGet(Constants.MOD_MENU_VERSION_URL, response => {
            if (!response) {
                Logger.warn("Actual mod menu version can't be fetched");
                // Menu.toast(en.toasts.mod_menu_version_not_fetched, 1);
                return;
            }

            // response should be like: {"script_version":"0.0"}
            const fetchedModmenuVersion = JSON.parse(response);

            if (fetchedModmenuVersion.script_version == ModPreferences.VERSION) {
                Logger.info("Mod menu is up to date");
                //Menu.toast(en.toasts.mod_menu_version_actual, 1);
            } else {
                Logger.warn("Mod menu version is outdated, redirecting to download page...");
                //Menu.toast(en.toasts.mod_menu_version_not_fetched, 1);
                JavaUtils.openURL(Constants.GITHUB_RELEASES_URL);
            }
        });
    }
}
