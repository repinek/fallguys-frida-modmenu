export const Constants = {
    // === Mod Menu URLs ===
    MOD_MENU_ICON_URL: "https://floyzi.github.io/images/obed-guys-present.png",
    MOD_MENU_VERSION_URL: "https://repinek.github.io/fallguys-modmenu/latest_version.json",
    MOD_MENU_CHANGELOG_URL: `https://repinek.github.io/fallguys-modmenu/changelogs.json`,

    // === Social URLs ===
    GITHUB_URL: "https://github.com/repinek/fallguys-frida-modmenu",
    GITHUB_RELEASES_URL: "https://github.com/repinek/fallguys-frida-modmenu/releases/latest",
    DISCORD_URL: "https://discord.gg/cNFJ73P6p3",
    FGTOOLS_MOBILE_URL: "https://github.com/floyzi/FGToolsMobile",

    // === Unity Logging ===
    UNITY_LOGGING: false,

    // == Spoof ===
    USE_SPOOF: true,
    SPOOF_VERSION_URL: "https://floyzi.github.io/fallguys/version.json",

    // === Custom Server ===
    USE_CUSTOM_SERVER: false,

    CUSTOM_LOGIN_URL: "https://login.fallguys.oncatapult.com/api/v1",
    CUSTOM_LOGIN_PORT: -1,
    CUSTOM_GATEWAY_URL: "gateway.fallguys.oncatapult.com",
    CUSTOM_GATEWAY_PORT: 443,
    IS_GATEWAY_SECURE: true,
    CUSTOM_ANALYTICS_URL: "analytics-gateway.fallguys.oncatapult.com",
    CUSTOM_ANALYTICS_PORT: 443,
    IS_ANALYTICS_SECURE: true,

    // === Token Login ===
    TOKEN_URL: "https://api.epicgames.dev/epic/oauth/v2/token",
    TOKEN_BODY: "grant_type=refresh_token&deployment_id=8bedfebaf56f406ebab78986ada3f9b3&scope=8w2sDwL5/GuUjeVbHZIxe1FAFwi+tuQI2msSCVIO+EA&refresh_token={0}",
    TOKEN_AUTHORIZATION: "Basic eHl6YTc4OTFtQURFRDB0UE5KRk9pRjhPbUkwRHdZMEo6OHcyc0R3TDUvR3VVamVWYkhaSXhlMUZBRndpK3R1UUkybXNTQ1ZJTytFQQ=="
} as const;
