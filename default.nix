{ pkgs ? import <nixpkgs> {}
}:

pkgs.stdenv.mkDerivation rec {
  name = "lldpd";
  src = pkgs.nix-gitignore.gitignoreSource [] ./.;
  configureFlags = [
    "--localstatedir=/var"
    "--enable-pie"
    "--with-snmp"
    "--with-systemdsystemunitdir=\${out}/lib/systemd/system"
  ];

  nativeBuildInputs = [ pkgs.pkgconfig pkgs.autoreconfHook ];
  buildInputs = [ pkgs.libevent pkgs.readline pkgs.net-snmp pkgs.openssl ];
  outputs = [ "out" "dev" "man" "doc" ];
}
