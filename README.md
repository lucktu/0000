

# Edge node

You need to start an edge node on each host you want to connect with the *same*
community.

Become root
```
./edge -f -d n2n0 -c mynetwork -u 99 -g 99 -k encryptme -m 00:FF:12:34:56:78 -a 192.168.254.1 -s 255.255.255.0 -l a.b.c.d:xyw
```
or
```
N2N_KEY=encryptme ./edge -f -d n2n0 -c mynetwork -u 99 -g 99 -m 00:FF:12:34:56:78 -a 192.168.254.1 -s 255.255.255.0 -l a.b.c.d:xyw
```

Once you have this worked out, you can drop the `-f` option to make edge detach
and run as a daemon.

Note that `-u`, `-g` and `-f` options are not available for Windows.

When running edge on Windows a compatile TAP network interface is required, the driver is included in the
[OpenVPN installer](https://openvpn.net/index.php/open-source/downloads.html). If multiple TAP adapters
exist in the system one can be specified using the `-d` parameter and the "Friendly Name" of the adapter
(the one shown in the Network Adapter List in the Control Pannel). If the name containes spaces be sure to use quotation marks around it.

# Supernode

You need to start the supernode once, it does not require any privileges.

1. `./supernode -l 1234 -v -f`

# IPv6 Support

This version of edge and supernode support transport inbetween over IPv6.

Start supernode either in IPv6 or IPv4 and IPv6 mode, by specifing `-6` or `-4` and `-6` switches.

```
./supernode -6 -f
```
or
```
./supernode -4 -6 -f
```

The default setting is to launch supernode in IPv4 only mode.

To use IPv6 with edge only the address needs to be specified for
the supernode.

```
./edge -f -v [ other options ] -l [2001:aa00:bb00::1]:1234
```

If DNS name resolution is required, then use the `-6` parameter,
to force a IPv6 address to be resolved.

```
./edge -f -v [ other options ] -6 -l example.com:1234
```


# IPv6 Support (Inner)

n2n supports the carriage of IPv6 packets within the n2n tunnel.

```
./edge -f -v [ other options ] -a 192.168.254.1 -s 255.255.255.0 -A fdf0:aa01:bb02::1/64
```

# Considerations of running edge as system service

## Use net_admin capabilities (LINUX)

This version of edge is capabilties aware and uses the `NET_ADMIN` capability if it is found
in its permissive set.

To use this feature set as root the admin capability:
```
setcap cap_net_admin+p ./edge
```

Edge can now be run as any user that has executive permission for edge.


## Running As a Daemon (UNIX)

Unless given `-f` as a command line option, edge will call `daemon(3)` after
successful setup. This causes the process to fork a child which closes `stdin`,
`stdout` and `stderr` then sets itself as process group leader. When this is done,
the edge command returns immediately and you will only see the edge process in
the process listings, eg. from `ps` or `top`.

If the edge command returns 0 then the daemon started successfully. If it
returns non-zero then edge failed to start up for some reason. When edge starts
running as a daemon, all logging goes to syslog `daemon.info` facility.


## Dropping Root Privileges and SUID-Root Executables (UNIX)

The edge node uses superuser privileges to create a TAP network interface
device. Once this is created root privileges are not required and can constitute
a security hazard if there is some way for an attacker to take control of an
edge process while it is running. Edge will drop to a non-privileged user if you
specify the `-u <uid>` and `-g <gid>` options. These are numeric IDs. Consult `/etc/passwd`.

You may choose to install edge SUID-root to do this:

1. Become root
2. `chown root:root edge`
3. `chmod +s edge`

Any user can now run edge. You may not want this, but it may be convenient and
safe if your host has only one login user.

## Systemd Service (LINUX)

Examples for an systemd service file are provided in the systemd/ folder.
The edge service uses AmbientCapabilities to set the net_admin capability
to run edge as a dynamically created user.

Systemd requires a Linux Kernel 4.3 or greater for this feature.


## SCM Service (WINDOWS)

edge and supernode can be installed as a Windows SCM service, consult the [`win32/install.ps1`](win32/install.ps1)
script in the repository.

When running as a service, edge and supernode are not attached to
a console, messages are logged in the Windows Event Log.

The commandline parameters are stored in `HKLM:\SOFTWARE\n2n\edge\Arguments` and `HKLM:\SOFTWARE\n2n\supernode\Arguments`.
They can be modified using `regedit` or an administrative PowerShell Console. Both entries are *MulitStrings*, so that parameters
containing spaces can properly supported but if this is not needed the registry entries can be of type *String* too.

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/lucktu/n2n6)
