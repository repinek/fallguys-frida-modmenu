export const obsidianConfig: Menu.ObsidianConfig = {
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
        closeFg: "#751616", // close
    },
    menu: {
        width: 300,
        height: 200,
        x: 100,
        y: 100,
        cornerRadius: 45 
    },
    icon: {
        size: 50,
        alpha: 1
    },
    strings: { // TODO: move to localization
        noOverlayPermission: "Overlay permission is needed to show the menu",
        hide: "<b>_</b>",
        close: "Close",
        hideCallback: "Icon hidden",
        killCallback: "Menu killed"
    }
};

