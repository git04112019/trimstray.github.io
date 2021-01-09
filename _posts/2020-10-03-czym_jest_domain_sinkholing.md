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

## Rozwiązywanie nazw

DNS (ang. _Domain Name System_) jest jedną z kluczowych części komunikacji, która pozwala na konwertowanie nazw alfabetycznych na numeryczne adresy. Dzięki temu, mając odpowiednio skonfigurowany serwer DNS, jesteśmy w stanie odpytywać go np. o adresy IP domen, które przechowuje.

Sam proces rozwiązywania nazw (czyli właśnie np. zamiany nazwy na adres IP) obejmuje mechanizm podobny do znajdowania domu na podstawie adresu. Przypuśćmy, że pilnie musimy stawić się w danym miejscu jednak znamy tylko adres. Odpytując specjalną bazę danych (w tym wypadku serwer DNS) jesteśmy w stanie uzyskać wynik będący dokładnymi współrzędnymi tego miejsca dzięki czemu poznamy ostateczną lokalizację.

Jak dobrze wiemy, każdemu urządzeniu podłączonemu do sieci nadawany jest adres IP, który jest niezbędny do zlokalizowania go w sieci. Na przykład, gdy chcemy załadować stronę internetową znajdującą się na zdalnym serwerze, musi nastąpić tłumaczenie między tym, co wpisujemy w swojej przeglądarce (np. <span class="h-b">example.com</span>), a zrozumiałym dla urządzeń i protokołów adresem IP (np. 192.168.10.25) niezbędnym do zlokalizowania strony internetowej. Ten proces tłumaczenia ma kluczowe znaczenie dla ładowania każdej strony internetowej.

Omówmy w takim razie cały proces jaki odbywa się podczas rozwiązywania nazwy domenowej, ponieważ jego zrozumienie jest kluczowe. Wygląda on podobnie do poniższego diagramu w typowym systemie GNU/Linux:

<p align="center">
  <img src="/assets/img/posts/ns_resolution.png">
</p>

Sam mechanizm i wszystkie kroki od wpisania w przeglądarce nazwy do uzyskania adresu IP a w konsekwencji wyświetlenia danego zasoby jest niezwykle fascynujący.

### Klient (przeglądarka)

Wpisując np. w przeglądarce adres <span class="h-b">example.com</span> w pierwszej kolejności przeglądarka sprawdza, czy domena znajduje się w jej lokalnej pamięci podręcznej. Jeśli odwiedzałeś jakiś czas temu tę domenę, przeglądarka może już wiedzieć, jaki jest jej adres IP i mieć tę wartość w swoim lokalnym buforze.

Pamięć podręczna przeglądarki zwykle przechowuje obiekty dosyć krótko a nie dłużej niż poprzez parametr czasu życiu (_ang. Time to Live_) — czyli adres jest przechowywany tak długo, jak został określony za pomocą tego parametru. Z drugiej strony, przeglądarki komunikują się z lokalnym resolverem więc TTL nie powinien mieć większego znaczenia. Po trzecie, przeglądarki posiadają wbudowane opcje, które sterują czasem życia rekordów, np. Firefox posiada parametry konfiguracyjne: <span class="h-b">network.dnsCacheExpiration</span> i <span class="h-b">network.dnsCacheExpirationGracePeriod</span> z domyślną wartością 60 sekund. Google Chrome i wbudowany wewnętrzny mechanizm rozpoznawania nazw DNS ignoruje TTL rekordów DNS i buforuje żądania DNS także przez 60 sekund.

### GNU libc

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

Druga z funkcji, tj. <span class="h-b">getaddrinfo</span> także służy do wyszukiwania DNS. Jest jednak znacznie bardziej zaawansowana (i bardziej przeładowana), ponieważ po drodze wywołuje znacznie więcej wywołań systemowych, tj. odczyt plików systemowych, ładowanie bibliotek czy otwieranie dodatkowych gniazd. Spójrz poniżej na statystyki ilości wywołań:

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

Generalnie tuż przed żądaniem DNS proces wykonuje wywołania systemowe i, jeśli trzeba rozwiązań nazwę z serwera DNS, pobiera adres IP serwera z pliku `/etc/resolv.conf`. <span class="h-b">getaddrinfo</span> pobiera informacje z `/etc/hosts`, czytając ten plik w całości za każdym razem, gdy wywołasz klienta.

Co niezwykle ciekawe, po uzyskaniu adresów IP przez tę funkcję, nie zwraca ona od razu odpowiedzi do klienta, tylko przeprowadza dodatkowo testy tych adresów, otwierając do nich gniazda i łącząc się z nimi:

```
socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("172.217.20.206")}, 16) = 0
getsockname(3, {sa_family=AF_INET, sin_port=htons(48043), sin_addr=inet_addr("192.168.43.56")}, [28->16]) = 0
close(3)                                = 0
socket(AF_INET6, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 3
connect(3, {sa_family=AF_INET6, sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2a00:1450:401b:805::200e", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)
close(3)
```

Oraz nie buforuje odpowiedzi (ogólnie obie nie buforują, aby zapewnić taką funkcję można użyć demona nscd), więc kolejne połączenia także są dosyć kosztowne przy jej wykorzystaniu.

Interesujące jest także to, że żaden z wymienionych wyżej plików nie jest znany procesom tak po prostu. Taką wiedzę uzyskują one dopiero po załadowaniu specjalnych współdzielonych bibliotek w czasie swojego wykonywania. Na przykład wywołując obie funkcje w dystrybucji Debianopodobnej:

- `/etc/hosts` jest znany z poziomu `libnss_files.so.2`
- `/etc/resolv.conf` jest znany z poziomu `libnss_dns.so.2`

### nsswitch.conf

Aby jeszcze bardziej skomplikować sprawę, musimy mieć świadomość, że proces pobiera listę takich źródeł w czasie wykonywania z innego pliku, tj. `/etc/nsswitch.conf`. Tak naprawdę GNU libc umożliwia skonfigurowanie kolejności, w jakiej funkcja czy proces, który z niej korzysta, próbuje uzyskać dostęp do usługi. Jest to kontrolowane właśnie przez plik `nsswitch.conf`. W przypadku dowolnej funkcji wyszukiwania obsługiwanej przez GNU libc plik ten zawiera wiersz z nazwami usług, które mają być używane.

Jeżeli chodzi o mechanizm rozwiązywania nazw, plik ten oczywiście przyjmuje różne wartości w zależności od systemu. Na przykład, w systemie FreeBSD 12.1 wygląda on tak:

```
hosts: files dns
```

Co oznacza taki wpis? Mówi on, że aby znaleźć hosta najpierw należy odpytać bibliotekę `libnss_files.so`. Jeśli to się nie powiedzie, należy odpytać bibliotekę `libnss_dns.so`. W dystrybucji CentOS 7.7 wpis hosts w tym pliku wygląda następująco:

```
hosts: files dns myhostname
```

Jest on niezwykle podobny jednak posiada dodatkową wartość. W tym wypadku mówi on, że aby znaleźć hosta najpierw należy odpytać bibliotekę `libnss_files.so`. Jeśli to się nie powiedzie, należy odpytać bibliotekę `libnss_dns.so`. Jeżeli obie próby zakończą się niepowodzeniem, odpytaj bibliotekę `libnss_myhostname.so`. Oczywiście w zależności od systemu czy dystrybucji wartości mogą znajdować się na innym miejscu.

Widzimy, że z poziomu pliku `nsswitch.conf` możemy zmuszać funkcje <span class="h-b">gethostbyname</span> i <span class="h-b">getaddrinfo</span> do wypróbowywania każdej z wymienionych usług, np. do przeszukiwania serwera DNS przed plikiem `/etc/hosts`. Jeśli wyszukiwanie powiedzie się, zwracany jest wynik, w przeciwnym razie sprawdzona zostanie następna usługa z listy.

Praktycznie w każdym systemie i dystrybucji plik `hosts` ma pierwszeństwo przed pozostałymi usługami. Informacje o nazwie hosta mogą się jednak zmieniać bardzo często, więc w niektórych sytuacjach serwer DNS powinien zawsze mieć najdokładniejsze dane, podczas gdy lokalny plik hostów traktowany jest jako kopia zapasowa tylko na wypadek awarii.

  > We wpisie hosts pliku `nsswitch.conf` może pojawić się jeszcze coś takiego jak mDNS. Jeżeli chcesz uzyskać więcej informacji na ten temat zerknij na odpowiedź [mDNS or Multicast DNS service](https://askubuntu.com/a/853284).

Wróćmy na chwilę do klientów i programów wykorzystujących omawiane funkcje. Mógłbyś pomyśleć: skoro każde z tych narzędzi uzyskuje ten sam wynik, więc na pewno wykorzystują te same mechanizmy. Tak naprawdę, różne programy uzyskują adres IP adresu na różne sposoby. Na przykład polecenie `ping` wykorzystuje mechanizm nsswitch, który z kolei może wykorzystać plik `/etc/hosts`, `/etc/resolv.conf` lub własnej nazwy hosta, aby uzyskać wynik.

Nie wszystkie narzędzia wykorzystują taki oto sposób. Na przykład komenda `host` jest typowym poleceniem służącym do odpytywania serwerów DNS. Wykorzystuje ona plik `/etc/resolv.conf` do ustalenia, które serwery DNS odpytać w celu uzyskania nazwy szukanego hosta. Tak naprawdę większość programów odwołuje się do tego pliku (jeśli zajdzie taka potrzeba) przy określaniu, który serwer DNS należy wykorzystać.

Podobnie sytuacja wygląda z narzędziem `nslookup` czy poleceniem `ping`. Pierwsze z nich wymusi wyszukiwanie DNS, podczas gdy `ping` będzie używać normalnej kolejności wyszukiwania nazw.

### DNS Server

Jeżeli procesom działającym w Twoim systemie nie udało się uzyskać adresu IP szukanej nazwy — pozostaje ostatni krok — czyli odpytanie zewnętrznych serwerów DNS. Jeśli wpiszesz w przeglądarce domenę <span class="h-b">example.com</span> mechanizmy systemu operacyjnego wyślą ​​zapytanie do skonfigurowanego serwera DNS z pytaniem właśnie o tę domenę.

Najczęściej takim serwerem jest serwer w sieci lokalnej (LAN). Jeśli odpytywany serwer DNS zna odpowiedź, ponieważ ostatnio zadano mu to samo pytanie, zwróci ją z pamięci podręcznej (o ile taki wpis nie wygasł). Jeśli odpytywany serwer DNS nie jest w stanie rozwiązać domeny, uruchomi procedurę odpytywania. W tym celu musi ustalić, który serwer DNS jest tzw. serwerem autorytatywnym, czyli takim serwerem, który na pewno potrafi rozwiązać szukaną przez nas nazwę.

Przed tym jednak lokalny serwer przekaże zapytanie do tzw. rekursywnego serwera DNS, często udostępnianego przez dostawcę usług internetowych (ISP). Rekursywny serwer DNS ma własną pamięć podręczną i jeśli ma adres IP, zwróci go do Ciebie. Jeśli nie, poprosi inny serwer DNS. Ponieważ pamięć podręczna serwera DNS zawiera tymczasowy magazyn rekordów DNS, będzie on szybko odpowiadał na żądania. Te serwery pamięci podręcznej DNS są nazywane nieautorytatywnymi serwerami DNS, ponieważ zapewniają rozwiązywanie żądań na podstawie wartości buforowanej uzyskanej z autorytatywnych serwerów DNS.

Następnym etapem są serwery nazw TLD, w tym przypadku serwer nazw TLD dla adresów <span class="h-b">.com</span>. Te serwery nie mają adresu IP, którego potrzebujemy, ale mogą wysłać żądanie DNS we właściwym kierunku. Widzimy, że pierwszym wysłanym zapytaniem będzie to, które dotyczy domeny głównego rzędu, tj. <span class="h-b">.</span> (root) aby znaleźć odpowiedni serwer dla domeny niższego rzędu, tj. <span class="h-b">.com</span>. Gdy uda się ustalić taki serwer, serwer DNS, który odpytywaliśmy, skomunikuje się z tym serwerem z ​​zapytaniem o serwer nazw.

To, co mają serwery nazw TLD, to lokalizacja autorytatywnego serwera nazw dla żądanej witryny. Autorytatywny serwer nazw odpowiada adresem IP dla <span class="h-b">example.com</span>, a rekursywny serwer DNS przechowuje go w lokalnej pamięci podręcznej DNS i zwraca adres do komputera.

Jeśli ma adres na przykład serwery nazw example.com, wyśle ​​oryginalne zapytanie dla <span class="h-b">www.example.com</span> do tego serwera i zwróci Ci odpowiedź (i umieści kopię w swojej pamięci podręcznej na wypadek, gdyby ktoś o to poprosił)

W internecie jest dużo komputerów, więc nie ma sensu umieszczać wszystkich zapisów w jednej dużej książce. Zamiast tego DNS jest podzielony na mniejsze książki lub domeny. Domeny mogą być bardzo duże, więc są dalej organizowane w mniejsze książki, zwane „strefami”. Żaden serwer DNS nie przechowuje wszystkich książek - byłoby to niepraktyczne.

Autorytatywny serwer nazw to miejsce, w którym administratorzy zarządzają nazwami serwerów i adresami IP swoich domen. Ilekroć administrator DNS chce dodać, zmienić lub usunąć nazwę serwera lub adres IP, dokonuje zmiany na swoim autorytatywnym serwerze DNS (czasami nazywanym „głównym serwerem DNS”). Istnieją również „podrzędne” serwery DNS; te serwery DNS przechowują kopie rekordów DNS swoich stref i domen.

Cały proces można podsumować poniższym diagramem:

<p align="center">
  <img src="/assets/img/posts/dns_hierarchy.png">
</p>

## Domain sinkholing
