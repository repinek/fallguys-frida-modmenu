import { AssemblyHelper } from "../core/assemblyHelper.js";
import { ModuleManager } from "../core/moduleManager.js";
import { BaseModule } from "../core/baseModule.js";

import { I18n } from "../i18n/i18n.js";

import { ModalType_enum, OkButtonType_enum, PopupManagerModule } from "./popup.js";
import { Logger } from "../utils/logger.js";

/*
 * === Permanent Ban Bypass Logic ===
 * Temporary bans can't be bypassed, but permament can be lol
 * 
 * 1. MainMenuViewModel::CheckAntiCheatClientServiceForError
 *    - Called by: MainMenuViewModel::TryConnect (Matchmaking start)
 *    - Behavior: Checks if AntiCheatClient::get_AllowOnlinePlay is false (since you're banned it's false)
 *    - Impact: If returns true, aborts matchmaking and calls MainMenuViewModel::ShowAntiCheatPopup
 *    So we just hook and return false
 *
 * 2. MainMenuViewModel::ShowAntiCheatPopup
 *    - Called by: MainMenuViewModel::_CheckRestrictedGameAccess_d__69::MoveNext coroutine
 *                 MainMenuViewModel::OnLoginSuccessful (once when you log in)
 *    - Behavior: Calls PopupManager::Show with title "anticheat_error_title".
 *    So we just hook, show our popup, and abort the original call
 */

export class BanBypassModule extends BaseModule {
    public name = "BanBypass Module";

    // Classes
    private MainMenuViewModel!: Il2Cpp.Class;

    // Methods
    private CheckAntiCheatClientServiceForError!: Il2Cpp.Method;
    private ShowAntiCheatPopup!: Il2Cpp.Method;

    public init(): void {
        this.MainMenuViewModel = AssemblyHelper.MTFGClient.class("FGClient.MainMenuViewModel");

        this.CheckAntiCheatClientServiceForError = this.MainMenuViewModel.method<boolean>("CheckAntiCheatClientServiceForError");
        // ShowAntiCheatPopup(AntiCheatError errorMessage, bool shouldQuit)
        this.ShowAntiCheatPopup = this.MainMenuViewModel.method("ShowAntiCheatPopup", 2);

        this.onEnable();
    }

    public override onEnable(): void {
        this.CheckAntiCheatClientServiceForError.implementation = function (): boolean {
            Logger.hook("CheckAntiCheatClientServiceForError called");
            return false;
        };

        this.ShowAntiCheatPopup.implementation = function (): void {
            Logger.hook("ShowAntiCheatPopup called");
            const popupModule = ModuleManager.get(PopupManagerModule);
            popupModule?.showPopup(I18n.t("messages.account_banned"), I18n.t("messages.account_banned_desc"), ModalType_enum.MT_OK, OkButtonType_enum.Green);
            return;
        };
    }
}
