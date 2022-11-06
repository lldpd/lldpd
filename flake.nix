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
        packages.default = pkgs.stdenv.mkDerivation rec {
          name = "lldpd";
          # We should be able to just use ./., but we have libevent as a submodule.
          # Currently, we should use:
          #  nix build ".?submodules=1"
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
        apps = {
          # Use:
          #  nix run ".?submodules=1#lldpcli" -- --help
          lldpd = {
            type = "app";
            program = "${self.packages."${system}".default}/bin/lldpd";
          };
          lldpcli = {
            type = "app";
            program = "${self.packages."${system}".default}/bin/lldpcli";
          };
        };
        devShells.default =
          let
            llvm = pkgs.llvmPackages_14;
            clang-tools = pkgs.clang-tools.override { llvmPackages = llvm; };
          in
          pkgs.mkShell {
            name = "lldpd-dev";
            buildInputs =
              self.packages."${system}".default.nativeBuildInputs ++
              self.packages."${system}".default.buildInputs ++ [
                clang-tools # clang-format (C)
                llvm.libclang.python # git-clang-format (C)
                pkgs.python3Packages.black # black (Python)

                # CI helper
                (pkgs.writeShellScriptBin "ci-helper" ''
                  set -eu
                  while [ $# -gt 0 ]; do
                    case $1 in
                      format-c)
                        echo "Run clang-format on C code..."
                        ${pkgs.git}/bin/git ls-files '*.c' '*.h' \
                          | xargs ${clang-tools}/bin/clang-format -i
                        ;;
                      format-python)
                        echo "Run black on Python code..."
                        ${pkgs.python3Packages.black}/bin/black tests/integration
                        ;;
                    esac
                    shift
                  done
                '')
              ];
          };
      });
}
