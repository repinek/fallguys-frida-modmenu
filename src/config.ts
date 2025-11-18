export namespace Config {
    export var ICON_URL = "https://floyzi.github.io/images/obed-guys-present.png";

    export var SPOOF_VERSION_URL = "https://floyzi.github.io/FGTools/mobile/version.json";
    export var VERSION_URL = "https://repinek.github.io/fallguys-modmenu/latest_version.json";
    export var GITHUB_URL = "https://github.com/repinek/fallguys-frida-modmenu";
    export var GITHUB_RELEASES_URL = "https://github.com/repinek/fallguys-frida-modmenu/releases/latest";
    export var DISCORD_URL = "https://discord.gg/cNFJ73P6p3";

    export var TELEPORT_COOLDOWN = 500;

    // === Login Spoof ===
    export var USE_SPOOF = true;
    export var customSignature: string;
    export var customGameVersion: string;

    // === Custom Server === 
    export var USE_CUSTOM_SERVER = false;
    export var CUSTOM_LOGIN_URL = "https://login.fallguys.oncatapult.com/api/v1"; 
    export var CUSTOM_LOGIN_PORT = -1;
    export var CUSTOM_GATEWAY_URL = "gateway.fallguys.oncatapult.com";
    export var CUSTOM_GATEWAY_PORT = 443;
    export var IS_GATEWAY_SECURE = true;
    export var CUSTOM_ANALYTICS_URL = "analytics-gateway.fallguys.oncatapult.com";
    export var CUSTOM_ANALYTICS_PORT = 443;
    export var IS_ANALYTICS_SECURE = true;

    export namespace Toggles {
        // === Movement ===
        export var toggle360Dives: boolean;
        export var toggleAirJump: boolean;
        export var toggleDontSendFallGuyState: boolean;

        export var toggleCustomSpeed: boolean;
        export var toggleCustomVelocity: boolean;
        export var toggleNegativeVelocity: boolean;
        export var toggleNoVelocity: boolean;

        export var toggleCustomJumpForce: boolean;
        export var toggleCustomDiveForce: boolean;

        // === Visuals ===
        export var toggleCustomFov: boolean;
        export var toggleFGDebug: boolean;
        export var toggleDisableAnalytics: boolean;
        export var toggleHideDoors: boolean;
        export var toggleShowQueuedPlayers: boolean;
    };

    export namespace CustomValues {
        export var normalMaxSpeed = 9.5;
        export var maxGravityVelocity = 40;
        export var jumpForce = 17.5;
        export var diveForce = 16.5;
        export var ResolutionScale = 1;
        export var FOV = 70;
    };

    export namespace DefaultValues {
        export var divePlayerSensitivity = 70;
        export var normalMaxSpeed = 9.5;
        export var carryMaxSpeed = 8;
        export var grabbingMaxSpeed = 5;
        export var maxGravityVelocity = 40;
        export var jumpForce = 17.5;
        export var airDiveForce = 7;
        export var diveForce = 16.5;
        export var diveMultiplier = diveForce / airDiveForce;
    };

    export namespace BuildInfo {
        // uhh here's probably will var
        export var PLATFORM = "android_ega"; // you can change it to other one here, refer BuildCatapultConfig hook
        export var gameVersion: string;
        export var spoofedGameVersion: string;
        export var originalSignature: string;
        export var spoofedSignature: string;
        export var unityVersion: string;
        export var buildNumber = "Local build";
        export var buildDate = "n/a";
    };
};