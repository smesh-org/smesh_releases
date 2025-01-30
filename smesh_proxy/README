SMesh v2.3 Installation instructions

I) Overview 

    SMesh runs on any linux distribution with a wireless device that
    supports ad-hoc (ibss) mode. It is currently available for x86, mips,
    and arm processors, and supports wireless routers like the Linksys WRT54G
    family.  SMesh can operate in three modes:

    1. OVERLAY MODE:  Data packets are routed through SMesh, and protocols
       like overlay multicast are available for lossless, fast handoff.
       In some slow processors like in the Linksys WRT54, the bandwith
       due to CPU usage is limitted to a couple of Mbps.  The kernel
       should have CONFIG_FILTER enabled when using this mode (although
       not required) for better performance.

    2. KERNEL SHORTEST PATH MODE:  SMesh manages the network topology and
       the clients, but data packets are routed through the kernel.
       This mode utilizes almost no CPU, and works with unmodified kernel
       in most linux-based systems.  While fast-handoff techniques
       are employed in this mode, overlay multicast is not available,
       which may sometimes result in some loss during handoff.  The full
       speed of the network is attainable in this mode when using low
       cost routers (No CPU limitation).  We recommend using this mode
       by default, before attempting other modes. 

    3. KERNEL REDUNDANT MULTIPATH MODE:  SMesh manages the network
       topology and the clients, but data packets are routed through
       the kernel.  This mode utilizes almost no CPU.  It employs overlay
       multicast inside the mesh through the kernel.  The SMesh iptables
       kernel patch and modules are needed for this mode to work
       (available through our website).  The full speed of the network
       is attainable in this mode when using low cost routers.


II) Linux Router Firmware Installation (i.e. WRT54G) 

    We recommend openwrt (www.openwrt.org) pptp distribution (we use
    Whiterussian RC5).  To support redundant multipath in kernel space,
    you need to compile a new kernel using the patch and modules in
    our website.  You do not need to have redundant multipath unless you
    intend to provide high quality-of-service for moving clients using
    real-time applications like VoIP.

    When installing from the box, you may need to change the bin file to 
    a trx file.  To do so, you can use dd as follows:
        dd if=openwrt-wrt-BLA.bin of=openwrt-wrt-BLA.trx bs=32 skip=1

    After succesfully installing the firmware, verify that you can ssh
    into the router.  Some firmwares require that you first go through
    the web browser to reset your password so that ssh is enabled.
    Proceed after you have successfully ssh into the box.

    Next, install at least the following packages: ip, libpcap, wl,
    and tcpdump.  There are two methods: 
    - Download and copy each package to the box and run 
      "ipkg install bla.ipk"
    - Get packages installed directly in the box using automatic
      download/install.  Use the web interface, or login and run "ipkg
      update", "ipkg install bla.ipk" which will get it from the Internet.


    SPECIAL INSTRUCTIONS: If completely compiling a different kernel
    yourself (not using openwrt), the following features should be in
    the enabled:
        Kernel:   have CONFIG_FILTER enabled to improve performance
                  in OVERLAY mode (optional).
        Busybox:  crond and crontab (dixie cron has some problems)
                  killall, grep, expr, ls_timestamp, sleep, tr, sed
        jffs2:    you should have a jffs2 partition enabled, with
                  800 KB of free space, if you want stable storage.


III) Configuring Mesh Node

    The mesh node must have a wireless interface configured in ibss
    (ad-hoc) mode, and setup with the correct parameters to be able to
    talk with other nodes in the mesh network.  We provided a file that
    can be used to setup each box. Although the file is meant to run on
    WRT54 routers and alike that use nvram, you can follow the file to
    see how to setup other linux boxes.  Modify the "smesh.wrt.setup"
    file provided with this software, copy it to the /tmp directory on
    the box, and run it.  Then, reboot the box, and you should be able to
    talk (i.e. ssh) to any other node on the mesh within wireless range.

    Each mesh box should be configured with a fixed rate on the wireless
    interface (i.e. 11Mbps, or 18Mbps) for a more stable network.
    However, it is not required (it may not behave consistently).
    We do not recommend fixed high speeds (36Mbps or more) unless the
    connectivity of the mesh will be very clean (loss rates tend to be
    higher at these rates).


IV) Configuring public and private keys for better mesh control

    This section is intended for users who wish to have easier control
    of all nodes in a mesh, as well as the ability to run commands,
    change configuration, or copy files and updates from one node into
    the complete mesh with one command.

    We will first configure the mesh so that any node can login to
    other nodes automatically. That is, all mesh nodes should share
    a public/private key.  Using ssh-gen, generate an rsa key.  Then,

    - copy rsa private/public key to /jffs/dropbear.pub and /jffs/dropbear.priv
    - copy/add public key to /etc/dropbear/authorized_keys
    - create a new file, /jffs/login.profile, and add the following lines:
        alias ssh='ssh -i /jffs/dropbear.priv'
        alias scp='scp -i /jffs/dropbear.priv'
    - copy login.profile to /tmp/.profile
  
    Exit and login back. You should now be able to login between boxes!
    Note that the login.profile is copied to /tmp/.profile when the box
    starts by the /etc/init.d/S70smesh file created by smesh.wrt.setup.
    If you bypassed the wrt.setup, you need to at least have this copy
    done somewhere in init.d


V)  Mesh Deployment

    At this point, the box can be deployed in the network.  Verify you
    can ssh between this box and another box in the wifi network before
    placing it in an specific static place where is harder to
    debug. After every box is deployed, you will be able to execute
    commands or distribute binaries to every box in SMesh from a single
    point / mesh node after this section.

    First, designate a root node that is connected to the WAN / Internet.
    Now draw a connectivity tree of your mesh network.  You should have a
    pretty good idea of which box can talk to which other box.  You should
    use ping, iperf, or rssi, to determine a good tree. Most likely,
    your knowledge of how far is each box to the other will suffice.
    Make sure that the tree does NOT contain any loop (otherwise, is
    not a tree :-).

    Now, on every box (ssh hopping through the mesh), configure the 
    following nvram value: 

        # NOTE: Every <ip_addr> is separated by a new line (hit enter).
        /usr/sbin/nvram set smesh_tree="<ip_addr>
        <ip_addr>
        <ip_addr>"
        /usr/sbin/nvram commit

    Every mesh node now knows the unique tree.  Now, copy autocommand.sh
    and autocopy.sh to the the root node in the /jffs/directory.  Then,
    run the following two commands:

        /jffs/autocopy.sh /jffs/autocopy.sh
        /jffs/autocopy.sh /jffs/autocommand.sh

    (Yes, autocopy copies itself to every box in the mesh :-)

    Congratulations! You are now able to run autocommand.sh and
    autocopy.sh to run a command or copy a file on every mesh node.
    For example:

        /jffs/autocommand.sh "/bin/uname -a" 
        /jffs/autocommand.sh "/bin/ps; /usr/bin/uptime"


VI) SMesh Installation  

    First, copy everything from the script and the appropiate bin
    directory to the directory where SMesh will be ran.  The following
    bin files are provided in our binary distribution: 
       x86    = intel pc / x86 executables
       mipsel = MIPS little endian (e.g., Linksys wrt54)
       mips   = MIPS big endian (e.g., meraki)
       arm    = ARM big-endian (e.g., ligowave, intel-xscale)

    In the wrt54, copy all files to /jffs. Then, make sure these
    files are executable:
        chmod 777 smesh_proxy
        chmod 777 spines

    The SMesh configuration file (smesh.conf) allows you to easily
    configure SMesh.  Make sure you DISABLE (remember to disable)
    any dhcp server on the mesh node as SMesh will provide you this
    functionality (In wrt54, this is dnsmasq, but it will be killed by
    S70smesh init script if you used the setup file in section IV).
    Your dhcp client for your WAN interface (Internet) should be
    enabled, if you intended so.  To start SMesh, just run the script
    (runSmesh).  Two processes should start: spines and smesh_proxy.
    Check /tmp/spines.snapshot to verify your topology and connectivity,
    and /tmp/smesh.snapshot for client connectivity information through
    SMesh. We basically display information based on this two snapshots
    in the website.  Also, you should set all mesh boxes to a fixed rate
    for a more stable metric on the mesh (i.e. 18).


VII) Additional Information


    SMesh kernel modes change kernel route tables, and must therefore
    issue system calls that performed the desired operation.  Although
    we evoke the shell version of ip for better compatibility, the
    performance can degrade in more limitted devices due to the shell
    system call from the C program (several hundred milliseconds per call
    in some cases on WRT54G).  We highly encourage you to download our
    shared library to iproute, which allows us to change route tables
    on the fly without the big overhead of the shell version.  To use,
    just copy iproute.so to the /lib directory.

    Sometimes, Windows may disconnect/reconnect due to sending a
    low signal strength in the medium (depends on wireless card
    as well). Also, if your mesh coverage has dead-spots, you may
    loose previous TCP connections due to Windows reseting the device.
    The solution is to disable media sending from your windows registry.
    Read: "How to disable the Media Sensing feature for TCP/IP in Windows"
    from Microsoft, if this is your case.

    To display a live-view of your network, as in our website, the root
    Internet gateway of your network should have the SMesh snapshot
    enabled in the smesh.conf file (only in the root node as this
    generates some traffic to aquire this information):

        SMESH_SNAPSHOT="-log /tmp/smesh.snapshot"

    The outside host that will retrieve the data for displaying on a
    website should have a private key to the box.  Then, install on the
    web server the graphviz visualization software (www.graphviz.org)
    and Perl (you probably have that). Then, modify the scripts on
    the live_view directory to reflect your directory paths. The tool
    generates the image files which need to be included on your HTML.
    Run the smesh_live.sh in a cron, and include the generated file on
    your HTML!

    For Kernel-space redundant multipath support, please follow the
    instructions from the website. We can also send you an already
    compiled version with this changes if you request it by email.

    If you like SMesh to start automatically when the router is pluged-in,
    you need to enter a cron job into the machine.  On the WRT, you
    can use the following command: 
        echo "* * * * * /jffs/runSmesh" | /bin/crontab -

    To support a diverse set of devices with older 802.11b cards, it may
    be necessary to enable 802.11g protection mode. However, this can
    decrease the attainable throughput. 

