{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
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
