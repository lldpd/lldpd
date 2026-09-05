{
  inputs = {
    nixpkgs.url = "nixpkgs";
  };
  outputs = { nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      perSystem = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages."${system}";
          llvm = pkgs.llvmPackages_14;
          clang-tools = pkgs.clang-tools.override { llvmPackages = llvm; };
          lldpd = pkgs.stdenv.mkDerivation rec {
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

            nativeBuildInputs = with pkgs; [ pkg-config autoreconfHook git check ];
            buildInputs = with pkgs; [ libevent readline net-snmp openssl ];
            outputs = [ "out" "dev" "man" "doc" ];
          };
        in
        {
          package = lldpd;
          devShell = pkgs.mkShell {
            name = "lldpd-dev";
            buildInputs =
              lldpd.nativeBuildInputs ++
              lldpd.buildInputs ++ [
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
                        ${pkgs.git}/bin/git ls-files '*.c' '*.h' '*.hpp' \
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
    in
    {
      packages = forAllSystems (system: {
        default = perSystem."${system}".package;
      });
      apps = forAllSystems (system: {
        # Use:
        #  nix run ".?submodules=1#lldpcli" -- --help
        lldpd = {
          type = "app";
          program = "${perSystem."${system}".package}/bin/lldpd";
        };
        lldpcli = {
          type = "app";
          program = "${perSystem."${system}".package}/bin/lldpcli";
        };
      });
      devShells = forAllSystems (system: {
        default = perSystem."${system}".devShell;
      });
    };
}
