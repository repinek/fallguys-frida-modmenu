{ 
  description = "fallguys-frida-modmenu development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = {
    nixpkgs,
    ...
  }:
  let 
    supportedSystems = [
      "x86_64-linux"
    ];

    forEachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
      pkgs = import nixpkgs {
        inherit system;
        config = {
          allowUnfree = true; # !!! 
          android_sdk.accept_license = true;
        };
      };
    });
  in {
    devShells = forEachSupportedSystem ({ pkgs }: 
    let
      buildToolsVersion = "34.0.0";
      androidComposition = pkgs.androidenv.composeAndroidPackages {
        buildToolsVersions = [ buildToolsVersion ];
      };
    in {
      default = pkgs.mkShell {
        buildInputs = with pkgs; [
          nodejs
          python314
          python314Packages.pip
          jre
          apksigner
          androidenv.androidPkgs.platform-tools
          apkeditor
          apktool
        ];
      
        shellHook = ''
          . .venv/bin/activate
          export PATH="${androidComposition.androidsdk}/libexec/android-sdk/build-tools/${buildToolsVersion}:$PATH"
        '';
      };
    });
  };
}
  