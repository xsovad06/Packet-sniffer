**IPK - Počítačové komunikace a sítě - Projekt 2**

# Sniffer paketů - varianta ZETA

Program `ipk-sniffer.cpp` slúži na zachytávanie packetov na určitom rozhraní(zariadení), kde môžeme definovat obmedzenia podľa vstupných parametrov programu.

# Príklad používania

Na začiatku je treba preložiť program, preklad sa spúšťa s príkazom `make`. Následne pre spustenie použijeme príkaz:
    `./ipk-sniffer`

Môžeme ešte použiť príkaz `make clean` pre odstránenie súborov s koncovkou ".o". 

# Možnosti parametrov

Za príkaz spustenia programu môžeme požívať následovné argumenty, ktoré sú ľubovoľne kombinovateľné a sú nepovinné:
    `-i <meno_rozhrania>` Meno zariadenia na odchytávanie packetov
    `-p <číslo_portu>`    Filtrovanie zadaného čísla portu
    `-t` alebo `--tcp`    Filtrovanie packetov s TCP protokolom
    `-u` alebo `--udp`    Filtrovanie packetov s UDP protokolom
    `-n <počet_packetov>` Počet odchytávaných packetov

Ďalej je možné použiť argument na vypísanie pomocnej správy, ktorý však nie je kombinovateľný s ostatnými argumantami. Pri kombinovaní sa program ukončí chybou.:
    `-h` alebo `--help`

# Odovzdané súbory
 `ipk-sniffer.cpp`
 `header.hpp`
 `manual.pdf`
 `README.md`
