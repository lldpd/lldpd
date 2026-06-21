class Lldpd < Formula
  desc "Implementation of IEEE 802.1ab (LLDP)"
  homepage "https://lldpd.github.io/"
  url "https://media.luffy.cx/files/lldpd/lldpd-1.0.20.tar.gz"
  sha256 "61b8cb22d4879e68f7825a2fb8e1e92abb4aba4773977cf0258bc32ed9f55450"
  license "ISC"

  livecheck do
    url :homepage
    regex(/href=.*?lldpd[._-]v?(\d+(?:\.\d+)+)\.t/i)
  end

  option "with-snmp", "Build SNMP subagent support"

  depends_on "pkgconf" => :build
  depends_on "libevent"
  depends_on "net-snmp" if build.with? "snmp"
  depends_on "readline"

  uses_from_macos "libxml2"

  def install
    readline = Formula["readline"]
    args = %W[
      --prefix=#{prefix}
      --sysconfdir=#{etc}
      --localstatedir=#{var}
      --with-privsep-chroot=/var/empty
      --with-readline
      --with-xml
      --without-launchddaemonsdir
      CPPFLAGS=-I#{readline.include}\ -DRONLY=1
      LDFLAGS=-L#{readline.lib}
    ]
    args << (build.with?("snmp") ? "--with-snmp" : "--without-snmp")

    system "./configure", *args, *std_configure_args
    system "make"
    system "make", "install"

    (var/"run").mkpath
  end

  def dscl(*args)
    result = `dscl . -#{args.join(' ')} 2> /dev/null`
    if $? != 0
      raise ErrorDuringExecution, "Failure while executing dscl: #{args.join(' ')}"
    end
    return result
  end

  # Create user and group if needed
  def caveats
    u = "_lldpd"
    unless Kernel.system "/usr/bin/dscl . -read /Users/#{u} &> /dev/null"
      # Find a free UID/GID
      uids = dscl("list /Users uid")
      gids = dscl("list /Groups gid")
      uid = 200
      while uids =~ Regexp.new("#{Regexp.escape(uid.to_s)}\n") || gids =~ Regexp.new("#{Regexp.escape(uid.to_s)}\n")
        uid += 1
      end
      s = <<~EOS
        You need to create a special user to run lldpd.
        Just type the following commands:
            sudo dscl . -create /Groups/#{u}
            sudo dscl . -create /Groups/#{u} PrimaryGroupID #{uid.to_s}
            sudo dscl . -create /Groups/#{u} Password "*"
            sudo dscl . -create /Groups/#{u} RealName "lldpd privilege separation group"
            sudo dscl . -create /Users/#{u}
            sudo dscl . -create /Users/#{u} UserShell /usr/bin/false
            sudo dscl . -create /Users/#{u} NFSHomeDirectory /var/empty
            sudo dscl . -create /Users/#{u} PrimaryGroupID #{uid.to_s}
            sudo dscl . -create /Users/#{u} UniqueID #{uid.to_s}
            sudo dscl . -create /Users/#{u} Password "*"
            sudo dscl . -create /Users/#{u} RealName "lldpd privilege separation user"
      EOS
      return s
    end
  end

  plist_options startup: true
  service do
    run build.with?("snmp") ? [opt_sbin/"lldpd", "-x"] : opt_sbin/"lldpd"
    keep_alive true
    require_root true
  end
end
