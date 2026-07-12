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
        };
      };
    });
  in {
    devShells = forEachSupportedSystem ({ pkgs }: {
      default = pkgs.mkShell {
        buildInputs = with pkgs; [
          nodejs
          python314
          python314Packages.pip
          jre
          apksigner
          androidenv.androidPkgs.platform-tools
          apkeditor
        ];
      
        shellHook = ''
          . .venv/bin/activate
        '';
      };
    });
  };
}
  