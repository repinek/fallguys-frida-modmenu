import { AssemblyHelper } from "../../core/assemblyHelper.js";
import { BaseModule } from "../../core/baseModule.js";

import { I18n } from "../../i18n/i18n.js";

import { Logger } from "../../logger/logger.js";

import { ModalType, OkButtonType, ModalMessageData } from "../../ui/popup/data/ModalMessageData.js";
import { PopupManager } from "../../ui/popup/popupManager.js";

/*
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
    public readonly name = "BanBypass";

    // Classes
    private MainMenuViewModel!: Il2Cpp.Class;

    // Methods
    private CheckAntiCheatClientServiceForError!: Il2Cpp.Method;
    private ShowAntiCheatPopup!: Il2Cpp.Method;

    public init(): void {
        this.MainMenuViewModel = AssemblyHelper.MTFGClient.class("FGClient.MainMenuViewModel");

        this.CheckAntiCheatClientServiceForError = this.MainMenuViewModel.method<boolean>("CheckAntiCheatClientServiceForError");
        // void ShowAntiCheatPopup(AntiCheatError errorMessage, bool shouldQuit)
        this.ShowAntiCheatPopup = this.MainMenuViewModel.method<void>("ShowAntiCheatPopup", 2);
    }

    public override initHooks(): void {
        const module = this;

        this.CheckAntiCheatClientServiceForError.implementation = function (): boolean {
            Logger.hook("CheckAntiCheatClientServiceForError called");
            return false;
        };

        this.ShowAntiCheatPopup.implementation = function (): void {
            Logger.hook("ShowAntiCheatPopup called");
            module.showBannedPopup();
            return;
        };
    }

    private showBannedPopup(): void {
        const data = ModalMessageData.create();
        data.Title = I18n.t("popups.ban_bypass.title");
        data.Message = I18n.t("popups.ban_bypass.message");
        data.ModalType = ModalType.MT_OK;
        data.OkButtonType = OkButtonType.Green;

        PopupManager.show(data);
    }
}
