# Projekt DNS Resolver

Tento projekt se zabývá vytvořením aplikace `dns`, která umožní zasílat DNS dotazy na DNS servery a vypisovat přijaté odpovědi v čitelné podobě na standardní výstup. Program `dns` podporuje komunikaci pomocí UDP a umí zpracovávat dotazy typu A, AAAA a PTR.

## Spuštění aplikace
./dns [-r] [-x] [-6] -s server [-p port] adresa

Popis parametrů:

- `-r`: Požadována rekurze (Recursion Desired = 1), jinak bez rekurze.
- `-x`: Reverzní dotaz místo přímého.
- `-6`: Dotaz typu AAAA místo výchozího A.
- `-s server`: IP adresa nebo doménové jméno DNS serveru, kam se má zaslat dotaz.
- `-p port`: Číslo portu, na který se má poslat dotaz (výchozí hodnota je 53).
- `adresa`: Dotazovaná adresa.

## Podporované typy dotazů

Program `dns` podporuje dotazy typu A (IPv4), AAAA (IPv6) a PTR (reverzní dotaz).

## Výstup aplikace

Program vypisuje informace o DNS odpovědi na standardní výstup ve formě:

- Zda je získaná odpověď autoritativní.
- Zda byla zjištěna rekurzivně.
- Zda byla odpověď zkrácena.

Dále vypisuje jednotlivé sekce a záznamy v odpovědi. Pro každou sekci se uvádí název a počet získaných záznamů. Pro každý záznam se vypisuje jeho název, typ, třída, TTL a data.

### Příklad výstupu:

Authoritative: No, Recursive: Yes, Truncated: No  
Question section (1)  
 www.fit.vut.cz, A, IN  
Answer section (1)  
 www.fit.vut.cz, A, IN, 14400, 147.229.9.26  
Authority section (0)  
Additional section (0)  

### Příklad výstupu s CNAME záznamem:

Authoritative: No, Recursive: Yes, Truncated: No  
Question section (1)  
www.github.com, A, IN  
Answer section (2)  
www.github.com, CNAME, IN, 3600, github.com  
github.com, A, IN, 60, 140.82.121.3  
Authority section (0)  
Additional section (0)  

## Doplňující informace

- Program `dns` se vypořádává s chybnými vstupy.
- Všechny chybové výpisy jsou vypisovány na standardní chybový výstup.
- Program `dns` je implementován v jazyce C++.
- Pro testy je použitá nestandartní knihovna gtest.
- Pokud nepřijde odpověď od DNS serveru je nutné ručně vypnout program pomocí `Ctrl+C`.

## Seznam odevzaných souborů

- Makefile
- README.md
- src/dns.cpp
- include/Helper.hpp
- include/Param.hpp
- include/DNSHeader.hpp
- include/DNSQuestion.hpp
- include/DNSAnswer.hpp
- include/SocketDataManager.hpp
- test/HelperTests.cpp