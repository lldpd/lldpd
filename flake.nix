{
  inputs = {
    nixpkgs.url = "nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, flake-utils, ... }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = inputs.nixpkgs.legacyPackages."${system}";
      in
      {
        defaultPackage = pkgs.stdenv.mkDerivation rec {
          name = "lldpd";
          # We should be able to just use ./., but we have libevent as a submodule.
          # Currently, an alternative would be to use:
          #  nix build "git+file://$(pwd)?submodules=1"
          # See:
          # - https://github.com/NixOS/nix/pull/5434
          # - https://github.com/NixOS/nix/pull/5497
          src = pkgs.nix-gitignore.gitignoreSource [ ] ./.;
          configureFlags = [
            "--localstatedir=/var"
            "--enable-pie"
            "--with-snmp"
            "--with-systemdsystemunitdir=\${out}/lib/systemd/system"
          ];

          nativeBuildInputs = with pkgs; [ pkgconfig autoreconfHook git check ];
          buildInputs = with pkgs; [ libevent readline net-snmp openssl ];
          outputs = [ "out" "dev" "man" "doc" ];
        };
      });
}
