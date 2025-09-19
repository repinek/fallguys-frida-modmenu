export namespace Config {
    // TODO: 
    // fix follow the leader teleport (add +y)
    export const VERSION = "2.02";
    export const VERSION_URL = "https://floyzi.github.io/FGTools/mobile/version.json";
    export const ICON_URL = "https://floyzi.github.io/images/obed-guys-present.png";

    // === Spoof ===
    export const use_spoof = true;
    export let customSignature: string;
    export let customGameVersion: string; 

    export namespace Toggles {
        // === Movement === 
        export let toggle360Dives: boolean;             // Toggle 360 dives
        export let toggleAirJump: boolean;              // Toggle air jump
        export let toggleDontSendFallGuyState: boolean; // Toggle sending Fall Guy state

        export let toggleCustomSpeed: boolean;          // Toggle custom normal max speed
        export let toggleCustomVelocity: boolean;       // Toggle custom max gravity velocity
        export let toggleNegativeVelocity: boolean;     // Toggle negative velocity
        export let toggleNoVelocity: boolean;           // Toggle disabling velocity completely

        export let toggleCustomJumpForce: boolean;      // Toggle custom jump force
        export let toggleCustomDiveForce: boolean;      // Toggle custom dive force

        // === Visuals === 
        export let toggleCustomFov: boolean;            // Toggle custom FOV
        export let toggleFGDebug: boolean;              // Toggle FG debug overlay
        export let toggleHideDoors: boolean;            // Toggle hiding real doors
        export let toggleShowQueuedPlayers: boolean;    // Toggle showing number of queued players
    }


    export namespace CustomValues {
        export let normalMaxSpeed = 9.5;
        export let maxGravityVelocity = 40;
        export let jumpForce = 17.5;
        export let diveForce = 16.5;
        export let ResolutionScale = 1;
        export let FOV = 70;
    }

    export namespace DefaultValues {
        export let divePlayerSensitivity = 70;
        export let normalMaxSpeed = 9.5;
        export let carryMaxSpeed = 8;
        export let grabbingMaxSpeed = 5;
        export let maxGravityVelocity = 40;
        export let jumpForce = 17.5;
        export let airDiveForce = 7;
        export let diveForce = 16.5;
    }

    export namespace BuildInfo {
        export let appVersion: string;
        export let original_signature: string;
        export let using_signature: string;
        export let current_platform = "android_ega"; // you can change it to other one, like pc_egs, ps5...
        export let unityVersion: string;
        export let buildNumber = "Local build";
        export let buildDate = "n/a";
    }
}