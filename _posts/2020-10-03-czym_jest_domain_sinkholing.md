---
layout: post
title: 'Czym jest domain sinkholing?'
description: "Mechanizm przechwytywania żądań DNS w celu ochrony użytkowników."
date: 2020-10-03 10:47:45
categories: [publications]
tags: [dns, security]
comments: true
favorite: false
toc: true
new: true
---

W tym wpisie chciałbym poruszyć niezwykle ciekawy temat związany z bezpieczeństwem systemu rozwiązywania nazw (mam nadzieję, że nie jest to zbytnie nadużycie) jakim jest DNS.

Technika DNS Sinkholing (ang. _sinkhole_ - lej) lub DNS Blackholing (ang. _blackhole_ - czarna dziura) jest używana do fałszowania wyników zwracanych z serwerów DNS. Dzięki temu jesteśmy w stanie ograniczyć lub odmówić dostępu do określonej domeny czy strony internetowej zwracając dla niej wskazany adres IP. Gdy użytkownik próbuje uzyskać dostęp do sinkholowanej domeny może zostać mu zwrócony zasób z informacjami opisującymi ograniczenia lub może być skierowany do specjalnego miejsca w sieci lokalnej tak, aby zapobiec wejścia na zainfekowaną domenę/stronę.

Oczywiście technika ta może zostać użyta do niecnych celów, ponieważ każdy może mieć taki rodzaj domen. Kluczowe jest jednak to, że ma to wpływ tylko na systemy, które używają tego konkretnego leja do rozpoznawania nazw DNS. Oczywiście główne serwery DNS lub serwery DNS kontrolowane przez dostawców usług internetowych będą miały wpływ na większą liczbę maszyn.

To tyle tytułem wstępu. Przejdźmy do dalszej części artykułu, w której przypomnimy sobie jak działa DNS i cały proces leżący u podstaw tego systemu a następnie omówimy dokładniej technikę sinkholingu.

## Jak działa DNS?

DNS (ang. _Domain Name System_) jest jedną z kluczowych części komunikacji, która pozwala na konwertowanie nazw alfabetycznych na numeryczne adresy. Dzięki temu, mając odpowiednio skonfigurowany serwer DNS, jesteśmy w stanie odpytywać go np. o adresy IP domen, które przechowuje.

Sam proces rozwiązywania nazw (czyli właśnie np. zamiany nazwy na adres IP) obejmuje mechanizm podobny do znajdowania domu na podstawie adresu. Przypuśćmy, że pilnie musimy stawić się w danym miejscu jednak znamy tylko adres. Odpytując specjalną bazę danych (w tym wypadku serwer DNS) jesteśmy w stanie uzyskać wynik będący dokładnymi współrzędnymi tego miejsca dzięki czemu poznamy ostateczną lokalizację.

Jak dobrze wiemy, każdemu urządzeniu podłączonemu do sieci nadawany jest adres IP, który jest niezbędny do zlokalizowania go w sieci. Na przykład, gdy chcemy załadować stronę internetową znajdującą się na zdalnym serwerze, musi nastąpić tłumaczenie między tym, co wpisujemy w swojej przeglądarce (np. <span class="h-b">example.com</span>), a zrozumiałym dla urządzeń i protokołów adresem IP (np. 192.168.10.25) niezbędnym do zlokalizowania strony internetowej. Ten proces tłumaczenia ma kluczowe znaczenie dla ładowania każdej strony internetowej.

### Proces rozwiązywania nazwy domenowej

Omówmy w takim razie cały proces jaki odbywa się podczas rozwiązywania nazwy domenowej, ponieważ jego zrozumienie jest kluczowe. Sam mechanizm i wszystkie kroki od wpisania w przeglądarce nazwy do uzyskania adresu IP a w konsekwencji wyświetlenia danego zasoby jest niezwykle fascynujący.

Wpisując w przeglądarce adres <span class="h-b">example.com</span> w pierwszej kolejności przeglądarka sprawdza, czy domena znajduje się w jej lokalnej pamięci podręcznej. Jeśli odwiedzałeś jakiś czas temu tę domenę, przeglądarka może już wiedzieć, jaki jest jej adres IP i mieć tę wartość w swoim lokalnym buforze.

Pamięć podręczna przeglądarki zwykle przechowuje obiekty dosyć krótko a nie dłużej niż poprzez parametr czasu życiu (_ang. Time to Live_) — czyli adres jest przechowywany tak długo, jak został określony za pomocą tego parametru. Z drugiej strony, przeglądarki komunikują się z lokalnym resolverem więc TTL nie powinien mieć większego znaczenia. Po trzecie, przeglądarki posiadają wbudowane opcje, które sterują czasem życia rekordów, np. Firefox posiada parametry konfiguracyjne: <span class="h-b">network.dnsCacheExpiration</span> i <span class="h-b">network.dnsCacheExpirationGracePeriod</span> z domyślną wartością 60 sekund. Google Chrome i wbudowany wewnętrzny mechanizm rozpoznawania nazw DNS ignoruje TTL rekordów DNS i buforuje żądania DNS także przez 60 sekund.

Przejdźmy dalej. Jeśli przeglądarka nie znajdzie odpowiedniego wpisu w swojej pamięci podręcznej, zacznie szukać dalej, aby przeprowadzić wyszukiwanie. I tutaj pojawia się kilka ciekawych kwestii.

Po pierwsze, istnieje kilka sposobów rozwiązywania nazw na tym poziomie i tak naprawdę nie ma jednej metody uzyskania wyszukiwania DNS. W systemie GNU/Linux istnieje biblioteka GNU libc, która dostarcza trzy różne interfejsy rozpoznawania nazw. Istnieje niskopoziomowa implementacja BSD [resolver(3)](https://man7.org/linux/man-pages/man3/resolver.3.html), jest także funkcja <span class="h-b">gethostbyname</span> i powiązane z nią dodatkowe funkcje, które implementują przestarzałą specyfikację POSIX, a także nowoczesna implementacja rozwiązywania nazw <span class="h-b">getaddrinfo</span> zgodne ze standardem POSIX.

Zajmijmy się tymi dwoma ostatnimi. W [oficjalnej dokumentacji](https://www.gnu.org/software/libc/manual/html_node/Host-Names.html) biblioteki libc zostały opisane tak:

<p class="ext">
  <em>
    You can use gethostbyname, gethostbyname2 or gethostbyaddr to search the hosts database for information about a particular host. The information is returned in a statically-allocated structure; you must copy the information if you need to save it across calls. You can also use getaddrinfo and getnameinfo to obtain this information.
  </em>
</p>

O ile nie określono inaczej, funkcja <span class="h-b">gethostbyname</span> używa domyślnej kolejności, tj. próbuje uzyskać wynik z lokalnego pliku `/etc/hosts` lub używa pliku `/etc/resolv.conf` w celu określenia (rozpoznaje serwery nazw domen zgodnie z opisem w dokumencie [RFC 883](https://tools.ietf.org/html/rfc883)) serwera DNS i wysłania do niego zapytania w celu uzyskania nazwy.

  > `gethostbyname` sprawdza, czy nazwa hosta może być rozwiązana przez odniesienie w lokalnym pliku (którego lokalizacja różni się w zależności od systemu operacyjnego) przed podjęciem próby odpytania serwera DNS. Jeśli `gethostbyname` nie ma rekordu w pamięci podręcznej ani nie może go znaleźć w pliku `hosts`, wysyła żądanie do serwera DNS skonfigurowanego w stosie sieciowym najczęściej właśnie przez plik lokalnego resolwera. Zazwyczaj jest to router lokalny lub buforujący serwer DNS usługodawcy internetowego.

Druga z funkcji, tj. `getaddrinfo` także służy do wyszukiwania DNS. Jest jednak znacznie bardziej zaawansowana (i bardziej przeładowana), ponieważ po drodze wywołuje znacznie więcej wywołań systemowych, tj. odczyt plików systemowych, ładowanie bibliotek czy otwieranie dodatkowych gniazd. Spójrz poniżej na statystyki ilości wywołań:

```
strace -c ./gethostbyname.out
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
  0.00    0.000000           0        10           read
  0.00    0.000000           0         1           write
  0.00    0.000000           0        10           close
  0.00    0.000000           0         1           stat
  0.00    0.000000           0         9           fstat
  0.00    0.000000           0         2           lseek
  0.00    0.000000           0        13           mmap
  0.00    0.000000           0         5           mprotect
  0.00    0.000000           0         2           munmap
  0.00    0.000000           0         3           brk
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         2           socket
  0.00    0.000000           0         2         2 connect
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         8           openat
------ ----------- ----------- --------- --------- ----------------
100.00    0.000000           0        71         3 total

strace -c ./getaddrinfo.out
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
  0.00    0.000000           0        12           read
  0.00    0.000000           0         1           write
  0.00    0.000000           0        14           close
  0.00    0.000000           0         1           stat
  0.00    0.000000           0        11           fstat
  0.00    0.000000           0         2           lseek
  0.00    0.000000           0        13           mmap
  0.00    0.000000           0         5           mprotect
  0.00    0.000000           0         2           munmap
  0.00    0.000000           0         3           brk
  0.00    0.000000           0         1         1 access
  0.00    0.000000           0         5           socket
  0.00    0.000000           0         4         2 connect
  0.00    0.000000           0         1           sendto
  0.00    0.000000           0         3           recvmsg
  0.00    0.000000           0         1           bind
  0.00    0.000000           0         3           getsockname
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           arch_prctl
  0.00    0.000000           0         9           openat
------ ----------- ----------- --------- --------- ----------------
100.00    0.000000           0        93         3 total
```

Oczywiście jest to przykład prostych programów napisanych w C odpytujących lokalnego hosta.

Generalnie tuż przed żądaniem DNS proces wykonuje wywołania systemowe i, jeśli trzeba rozwiązań nazwę z serwera DNS, pobiera adres IP serwera z pliku `/etc/resolv.conf`. `getaddrinfo` pobiera informacje z `/etc/hosts`, czytając ten plik w całości za każdym razem, gdy wywołasz klienta.

Co ciekawe, żaden z tych plików nie jest znany procesom tak po prostu. Taką wiedzę uzyskują one dopiero po załadowaniu specjalnych współdzielonych bibliotek w czasie swojego wykonywania. Na przykład wywołując obie funkcje w dystrybucji Debianopodobnej:

- `/etc/hosts` jest znany z poziomu `libnss_files.so.2`
- `/etc/resolv.conf` jest znany z poziomu `libnss_dns.so.2`

Aby jeszcze bardziej skomplikować sprawę, musimy mieć świadomość, że proces pobiera listę takich źródeł w czasie wykonywania z innego pliku, `/etc/nsswitch.conf`. Plik ten oczywiście przyjmuje różne wartości w zależności od systemu. Na przykład, w systemie FreeBSD 12.1 wygląda on tak:

```
hosts: files dns
```

Co oznacza taki wpis? Mówi on, że aby znaleźć hosta najpierw należy odpytać bibliotekę `libnss_files.so`. Jeśli to się nie powiedzie, należy odpytać bibliotekę `libnss_dns.so`. W dystrybucji CentOS 7.7.1908 wpis hosts w tym pliku wygląda następująco:

```
hosts: files dns myhostname
```

Jest on niezwykle podobny jednak posiada dodatkową wartość. W tym wypadku mówi on, że aby znaleźć hosta najpierw należy odpytać bibliotekę `libnss_files.so`. Jeśli to się nie powiedzie, należy odpytać bibliotekę `libnss_dns.so`. Jeżeli obie próby zakończą się niepowodzeniem, odpytaj bibliotekę `libnss_myhostname.so`. Oczywiście w zależności od systemu czy dystrybucji wartości mogą znajdować się na innym miejscu.

  > We wpisie hosts pliku `nsswitch.conf` może pojawić się jeszcze coś takiego jak mDNS. Jeżeli chcesz uzyskać więcej informacji na ten temat zerknij na odpowiedź [mDNS or Multicast DNS service](https://askubuntu.com/a/853284).

Co niezwykle ciekawe, po uzyskaniu adresów IP przez tę funkcję, nie zwraca ona od razu odpowiedzi do klienta, tylko przeprowadza dodatkowo testy tych adresów, otwierając do nich gniazda i łącząc się z nimi:

```
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0
getsockname(3, {sa_family=AF_INET, sin_port=htons(43582), sin_addr=inet_addr("127.0.0.1")}, [28->16]) = 0
close(3)                                = 0
socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
connect(3, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0
getsockname(3, {sa_family=AF_INET6, sin6_port=htons(51323), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, [28]) = 0
close(3)
```

Oraz nie buforuje odpowiedzi (ogólnie obie nie buforują, aby zapewnić taką funkcję można użyć demona nscd), więc kolejne połączenia także są dosyć kosztowne przy jej wykorzystaniu.
