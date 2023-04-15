{
  inputs = {
    nixpkgs.url = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = inputs.nixpkgs.legacyPackages."${system}";
        pythonEnv = pkgs.poetry2nix.mkPoetryEnv {
          projectDir = ./.;
          overrides = pkgs.poetry2nix.overrides.withDefaults (self: super: {
            pytest = super.pytest.overridePythonAttrs (
              old: { doCheck = false; doInstallCheck = false; }
            );
          });
        };
      in
      {
        apps = {
          poetry = {
            type = "app";
            program = "${pkgs.poetry}/bin/poetry";
          };
        };
        devShell = pythonEnv.env.overrideAttrs (oldAttrs: {
          name = "lldpd-website";
          buildInputs = [
            # Build
            pkgs.git
            pkgs.git-annex
            pkgs.openssl
            pkgs.python3Packages.invoke
            pkgs.lessc
            pkgs.optipng
          ];
          shellHook = "";
        });
      });
}
