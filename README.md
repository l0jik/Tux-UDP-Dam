# Tux-UDP-Dam
.sh Outgoing UDP Packets Filter

Outgoing UDP packets disturbance

Tux-UDP-Dam script v0.1 Author: l0jik Lang: ENG-IT

ENG

ABOUT
The purpose of these scripts for Windows and Linux is to block UDP outgoing packets. Such a block creates a dam for spywares, thus interfering with Remote Controls and Desktop Sharing.

All outgoing UDP packets will be blocked, so that the user will not be able to communicate through live calls, both audio and video.

It’s still an ongoing project, experimental in a way. But, had you ever been spied upon, It comes quite handy as a solution. TO NAVIGATE, remember to enable DNS!

IT

Lo scopo di questi script per Windows e Linux è bloccare i pacchetti UDP in uscita. Un tale blocco determina una difesa contro gli spyware, pertanto interferendo con i Remote Control e il Desktop Sharing.

Tutti i pacchetti UDP in uscita verranno fermati, perciò l’utente non sarà in grado Di comunicare via call, sia audio che video.

E’ un progetto ancora in sviluppo, in un certo senso sperimentale. Ma, qualora siate mai stati spiati, è una soluzione piuttosto comoda. PER NAVIGARE, ricorda di abilitare il DNS!

DEPENDENCIES
nftables iproute2 systemd sha256sum (coreutils)

and

cgroup (cgroup v2 must be in /sys/fs/cgroup/cgroup.controllers path)

USAGE (it needs root privileges)-

sudo ./tux_udp_dam.sh enable [--allow-dns] [--allow-program PATH ...]

sudo ./tux_udp_dam.sh disable

sudo ./tux_udp_dam.sh status

ENABLING DNS
The following command:

sudo ./tux_udp_dam.sh enable --allow-dns

enables port 53.
