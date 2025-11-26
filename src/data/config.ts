export const Config = {
    MOD_MENU_ICON_URL: "https://floyzi.github.io/images/obed-guys-present.png",

    SPOOF_VERSION_URL: "https://floyzi.github.io/FGTools/mobile/version.json",
    MOD_MENU_VERSION_URL: "https://repinek.github.io/fallguys-modmenu/latest_version.json",
    GITHUB_URL: "https://github.com/repinek/fallguys-frida-modmenu",
    GITHUB_RELEASES_URL: "https://github.com/repinek/fallguys-frida-modmenu/releases/latest",
    DISCORD_INVITE_URL: "https://discord.gg/cNFJ73P6p3",

    TELEPORT_COOLDOWN: 500,

    // === Login Spoof ===
    USE_SPOOF: true,

    // === Custom Server ===
    // refer to BuildCatapultConfig_method.implementation
    USE_CUSTOM_SERVER: false,

    CUSTOM_LOGIN_URL: "https://login.fallguys.oncatapult.com/api/v1",
    CUSTOM_LOGIN_PORT: -1,
    CUSTOM_GATEWAY_URL: "gateway.fallguys.oncatapult.com",
    CUSTOM_GATEWAY_PORT: 443,
    IS_GATEWAY_SECURE: true,
    CUSTOM_ANALYTICS_URL: "analytics-gateway.fallguys.oncatapult.com",
    CUSTOM_ANALYTICS_PORT: 443,
    IS_ANALYTICS_SECURE: true,

    Toggles: {
        // === Movement ===
        toggle360Dives: false,
        toggleAirJump: false,
        toggleDontSendFallGuyState: false,

        toggleCustomSpeed: false,
        toggleCustomVelocity: false,
        toggleNegativeVelocity: false,
        toggleNoVelocity: false,

        toggleCustomJumpForce: false,
        toggleCustomDiveForce: false,

        // === Visuals ===
        toggleCustomFov: false,
        toggleFGDebug: false,
        toggleDisableAnalytics: false,
        toggleHideDoors: false,
        toggleShowQueuedPlayers: false
    },

    CustomValues: {
        normalMaxSpeed: 9.5,
        maxGravityVelocity: 40,
        jumpForce: 17.5,
        diveForce: 16.5,
        ResolutionScale: 1,
        FOV: 70
    },

    DefaultValues: {
        divePlayerSensitivity: 70,
        normalMaxSpeed: 9.5,
        carryMaxSpeed: 8,
        grabbingMaxSpeed: 5,
        maxGravityVelocity: 40,
        jumpForce: 17.5,
        airDiveForce: 7,
        diveForce: 16.5,
        diveMultiplier: 16.5 / 7 // diveForce / airDiveForce
    },

    BuildInfo: {
        PLATFORM: "ports3_2",
        spoofedGameVersion: "" as string,
        originalSignature: "" as string,
        spoofedSignature: "" as string
    }
};
