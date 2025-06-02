export namespace Config {
    
    // TODO: 
    // fix follow the leader teleport (add +y)
    export const version = "2.02";

    export namespace Toggles {
        // === Movement === 
        export let enable360Dives: boolean;                 // 360 Dives toggle
        export let enableAirJump: boolean;                  // Air Jump toggle
        export let enableDontSendFallGuyState: boolean;     // Don't send Fall Guys State toggle
        
        export let enableCustomSpeed: boolean;              // Normal Max Speed changing 
        
        export let enableCustomVelocity: boolean;           // Max Gravity Velocity changing
        export let enableNegativeVelocity: boolean;         // Negative Velocity toggle
        export let enableNoVelocity: boolean;               // No Velocity toggle
        
        export let enableCustomJumpForce: boolean;          // Jump Force Ultimate Party changing
        export let enableCustomDiveForce: boolean;          // Dive Force changing 

        // === Visuals === 
        export let enableCustomFOV: boolean;                // FOV changing
        export let enableFGDebug: boolean;                  // FGDebug toggle
        export let enableHideDoors: boolean;                // Hide Real Doors toggle
        export let enableShowQueuedPlayers: boolean;        // Show Number of Queued Players toggle

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
        export let unityVersion: string;
        export let buildNumber = "Local build";
        export let commit = "(no commit info)";
        export let buildDate = "n/a";
        export let EOSVersion: string; // EOS SDK
    }
}