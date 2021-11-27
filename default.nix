{ pkgs ? import <nixpkgs> {}
}:

with pkgs;
stdenv.mkDerivation rec {
  name = "lldpd";
  src = nix-gitignore.gitignoreSource [] ./.;
  configureFlags = [
    "--localstatedir=/var"
    "--enable-pie"
    "--with-snmp"
    "--with-systemdsystemunitdir=\${out}/lib/systemd/system"
  ];

  nativeBuildInputs = [ pkgconfig autoreconfHook ];
  buildInputs = [ libevent readline net-snmp openssl ];
  outputs = [ "out" "dev" "man" "doc" ];
}
