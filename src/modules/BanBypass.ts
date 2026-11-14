import { AssemblyHelper } from "../core/AssemblyHelper";

import { I18n } from "../i18n/I18n";

import { Logger } from "../logger/Logger";

import { ModalType, OkButtonType, ModalMessageData } from "../ui/popup/data/ModalMessageData";
import { PopupManager } from "../ui/popup/PopupManager";

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

export class BanBypass {
    static init(): void {
        const MainMenuViewModel = AssemblyHelper.MTFGClient.class("FGClient.MainMenuViewModel");

        MainMenuViewModel.method<boolean>("CheckAntiCheatClientServiceForError").implementation = this.checkHook;
        // void ShowAntiCheatPopup(AntiCheatError errorMessage, bool shouldQuit)
        MainMenuViewModel.method<void>("ShowAntiCheatPopup", 2).implementation = this.popupHook;

        Logger.info("[BanBypass::init] Initialized");
    }

    private static checkHook(): boolean {
        Logger.hook("CheckAntiCheatClientServiceForError called");
        return false;
    }

    private static popupHook(): void {
        Logger.hook("ShowAntiCheatPopup called");
        BanBypass.showBannedPopup();
        return;
    }

    private static showBannedPopup(): void {
        const data = ModalMessageData.create();
        data.Title = I18n.t("popups.ban_bypass.title");
        data.Message = I18n.t("popups.ban_bypass.message");
        data.ModalType = ModalType.MT_OK;
        data.OkButtonType = OkButtonType.Green;

        PopupManager.show(data);
    }
}
