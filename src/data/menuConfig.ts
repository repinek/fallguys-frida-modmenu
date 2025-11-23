import { I18n } from "../i18n/i18n.js";

export const ObsidianConfig: Menu.ObsidianConfig = {
    color: {
        primaryText: "#FFFFFF",
        secondaryText: "#FFFFFF",
        buttonBg: "#326647", // button
        layoutBg: "#1C1C1C", // main
        collapseBg: "#3B3B3B",
        categoryBg: "#296368",
        menu: "#0D0D0D", // back
        tabFocusedBg: "#454545",
        tabUnfocusedBg: "#3E3E3E",
        hideFg: "#55514F", // hide
        closeFg: "#751616" // close
    },
    menu: {
        width: 350,
        height: 200,
        x: 100,
        y: 100,
        cornerRadius: 45
    },
    icon: {
        size: 50,
        alpha: 1
    },
    strings: {
        noOverlayPermission: I18n.t("menu.toasts.no_overlay_permission"),
        hide: I18n.t("menu.toasts.hide_button"),
        close: I18n.t("menu.toasts.close_button"),
        hideCallback: I18n.t("menu.toasts.hide_callback"),
        killCallback: I18n.t("menu.toasts.kill_callback") // hold hide to kill menu
    }
};
