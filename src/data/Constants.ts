export const Constants = {
    // === Mod Menu URLs ===
    MOD_MENU_ICON_URL: "https://floyzi.github.io/images/obed-guys-present.png",
    MOD_MENU_VERSION_URL: "https://repinek.github.io/fallguys-modmenu/latest_versionon",
    MOD_MENU_CHANGELOG_URL: `https://repinek.github.io/fallguys-modmenu/changelogson`,

    // === Social URLs ===
    GITHUB_URL: "https://github.com/repinek/fallguys-frida-modmenu",
    GITHUB_RELEASES_URL: "https://github.com/repinek/fallguys-frida-modmenu/releases/latest",
    DISCORD_URL: "https://discord.gg/cNFJ73P6p3",

    // === Unity Logging ===
    UNITY_LOGGING: false,

    // == Spoof ===
    USE_SPOOF: true,
    SPOOF_VERSION_URL: "https://floyzi.github.io/fallguys/versionon",
    PLATFORM: "android_ega", // android_ega is default

    // === Custom Server ===
    USE_CUSTOM_SERVER: false,

    CUSTOM_LOGIN_URL: "https://login.fallguys.oncatapult.com/api/v1",
    CUSTOM_LOGIN_PORT: -1,
    CUSTOM_GATEWAY_URL: "gateway.fallguys.oncatapult.com",
    CUSTOM_GATEWAY_PORT: 443,
    IS_GATEWAY_SECURE: true,
    CUSTOM_ANALYTICS_URL: "analytics-gateway.fallguys.oncatapult.com",
    CUSTOM_ANALYTICS_PORT: 443,
    IS_ANALYTICS_SECURE: true
} as const;
