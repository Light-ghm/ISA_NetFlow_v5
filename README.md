# NetFlow v5 generátor z .pcap súborov

**Autor:** Marián Backa (xbacka01)

**Hodnotenie:** 15/20b

**Spustenie:** 

- Preloženie programu sa vykoná príkazom `make`.

- **Spustenie programu:** ```./flow [-f <file>] [-c <netflow collector>[:<port>]] [-a <active timer>][-i <inactive timer>] [-m <count>]```

**Detailný popis:** manual.pdf

**Krátky popis programu:** 

Ciel’om projektu je vytvorit’ program na získanie tokov rekordov z jednotilivych paketov .pcap súboru.
Ide teda o analyzu zachyteného dátového toku. Jednotlivé pakety z pcap súboru združujeme do takzvanych tokov na základe spoločných vlastností a udrzujeme o nich užitočné informácie. 
Ako programátorom sledovanie tokov nám umožňuje omnoho rýchlejšie a jednoduchšie pochopiť, čo sa na sieti dialo ako keby sme sa snažili analyzovať jednotlive pakety 
po jednom ručne. Program posiela vygenerované toky na kolektor.
