---
layout: post
title: "NGINX: Optymalizacja sesji SSL/TLS"
description: "Omówienie i optymalizacja wartości parametrów sesji SSL/TLS."
date: 2019-07-21 23:04:51
categories: [tls]
tags: [http, https, ssl, tls, nginx, best-practices, performance, session, cache, tickets, buffer]
comments: true
favorite: false
toc: true
last_modified_at: 2020-06-10 00:00:00 +0000
---

Domyślnie konfiguracja sesji SSL/TLS w NGINX nie jest optymalna. Na przykład wbudowana pamięć podręczna może być używana tylko przez jeden proces roboczy, co może powodować fragmentację pamięci, dlatego o wiele lepiej jest używać jej współdzielonej wersji, która eliminuje ten problem. Optymalizacji powinny podlegać także dodatkowe parametry tj. odpowiedzialne za rozmiar rekordów TLS czy czas utrzymywania sesji w pamięci podręcznej.

Na przykład, aby zmniejszyć koszty obliczeń kryptograficznych i podróży komunikatów w obie strony, stosuje się mechanizm wznawiania sesji TLS. Polega on na przechowywaniu oraz udostępnianiu tych samych wynegocjowanych parametrów między wieloma połączeniami. Wznowienie sesji jest ważnym elementem optymalizacyjnym, ponieważ skrócony uścisk dłoni oznacza, że większość żądań nie wymaga pełnego uzgadniania, eliminuje opóźnienia i znacznie zmniejsza koszty obliczeniowe dla obu stron.

Niestety wiążą się z tym pewne problemy, zwłaszcza związane z bezpieczeństwem. Umożliwia to wykorzystanie techniki zwanej atakiem przedłużającym (ang. _Prolongation Attack_), który w dużym skrócie, polega na śledzeniu użytkowników na podstawie mechanizmu (danych) wznawiania sesji TLS (spójrz na pracę [Tracking Users across the Web via TLS Session Resumption]({{ site.url }}/assets/pdfs/2018-12-06-Sy-ACSAC-Tracking_Users_across_the_Web_via_TLS_Session_Resumption.pdf) <sup>[PDF]</sup>). Oczywiście rodzi to także pewien dysonans, ponieważ aby skorzystać z funkcji PFS (ang. _Perfect Forward Secrecy_), musimy upewnić się, że użyty materiał kryptograficzny związany z TLS nie jest w żaden sposób przechowywany.

Tak naprawdę nie ma jednoznacznych odpowiedzi, które dotyczą odpowiednich wartości parametrów sesji SSL/TLS. W rzeczywistości, typowe serwery internetowe zamykają połączenia po kilkunastu sekundach bezczynności, ale będą pamiętać sesje (zestaw szyfrów i klucze) znacznie dłużej — prawdopodobnie przez godziny lub nawet dni. Moim zdaniem należy zrównoważyć wydajność (nie chcemy, aby użytkownicy używali pełnego uzgadniania przy każdym połączeniu) i bezpieczeństwo (nie chcemy zbytnio narażać komunikacji TLS na szwank). Co więcej, nie ma jednego standardu i różne projekty dyktują różne ustawienia.

## ssl_session_cache

Pierwszy z parametrów zwiększa ogólną wydajność połączeń (zwłaszcza połączeń typu Keep-Alive). Wartość 10 MB jest dobrym punktem wyjścia (1 MB współdzielonej pamięci podręcznej może pomieścić około 4000 sesji), który jest także odpowiednim, aby pamięć podręczna mogła być zmieniana codziennie. Dzięki parametrowi `shared` pamięć dla połączeń SSL jest współdzielona przez wszystkie procesy robocze (co więcej pamięć podręczna o tej samej nazwie może być używana na kilku serwerach wirtualnych).

Włączenie buforowania sesji pomaga zmniejszyć obciążenie procesora oraz zwiększa wydajność z punktu widzenia klientów, ponieważ eliminuje potrzebę przeprowadzania nowego (i czasochłonnego) uzgadniania SSL/TLS przy każdym żądaniu.

Oczywiście nie ma róży bez kolców. Jednym z powodów, dla których nie należy używać bardzo dużej pamięci podręcznej, jest to, że większość implementacji nie usuwa z niej żadnych rekordów. Nawet wygasłe sesje mogą nadal się w niej znajdować i można je odzyskać!

Przykład konfiguracji:

```nginx
# context: http, server
# default: none
ssl_session_cache shared:NGX_SSL_CACHE:10m;
```

Oficjalna dokumentacja: [ssl_session_cache](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_session_cache).

## ssl_session_timeout

Zgodnie z [RFC 5077 - Ticket Lifetime](https://tools.ietf.org/html/rfc5077#section-5.6) <sup>[IETF]</sup>, sesje nie powinny być utrzymywane dłużej niż 24 godziny (jest to maksymalny czas dla sesji SSL/TLS). Jakiś czas temu znalazłem rekomendację, aby dyrektywa ta miała jeszcze mniejszą, wręcz bardzo niską wartość ustawioną na ok. 15 minut (co ciekawe, dokumentacja serwera NGINX ustawia wartość domyślną na 5 minut). Ma to zapobiegać nadużyciom przez reklamodawców (trackerów) takich jak Google i Facebook. Nigdy nie stosowałem tak niskich wartości, jednak myślę, że w jakiś sposób może to mieć sens.

Jeśli stosujemy szyfry wykorzystujące utajnianie z wyprzedzeniem, musimy upewnić się, że okres ważności parametrów sesji nie jest zbyt długi, ponieważ ewentualna kradzież zawartości pamięci podręcznej pozwala odszyfrować wszystkie sesje, których parametry są w niej zawarte. Jeśli sesje będą przechowywane przez 24h, osoba atakująca może odszyfrować maksymalnie 24 godziny komunikacji sieciowej.

W tym miejscu chciałbym zacytować wypowiedź twórcy serwisu [Hardenize](https://www.hardenize.com/), a także autora świetnej książki [Bulletproof SSL and TLS: Understanding and deploying SSL/TLS and PKI to secure servers and web applications.](https://www.feistyduck.com/books/bulletproof-ssl-and-tls/):

<p class="ext">
  <em>
    These days I'd probably reduce the maximum session duration to 4 hours, down from 24 hours currently in my book. But that's largely based on a gut feeling that 4 hours is enough for you to reap the performance benefits, and using a shorter lifetime is always better.
  </em>
</p>

Myślę, że wartość 4h jest rozsądną i jedną z optymalnych wartości.

Przykład konfiguracji:

```nginx
# context: http, server
# default: 5m
ssl_session_timeout 4h;
```

Oficjalna dokumentacja: [ssl_session_timeout](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_session_timeout).

## ssl_session_tickets

Kolejną modyfikacją mogą być klucze sesji lub inaczej bilety sesji. Zawierają one pełny stan sesji (w tym klucz wynegocjowany między klientem a serwerem czy wykorzystywane zestawy szyfrów), dzięki czemu zmniejszają obciążenie uścisku dłoni, który jak wiemy, jest najbardziej kosztowny w całym procesie uzgadniania. Taki mechanizm przydaje się szczególnie gdy dojdzie np. do zerwania sesji. Wszystkie informacje wymagane do kontynuowania sesji są tam zawarte, więc serwer może wznowić sesję, wykorzystując wcześniejsze parametry. Gdy klient obsługuje bilety sesji, serwer zaszyfruje klucz sesji kluczem, który posiada tylko serwer, kluczem szyfrowania biletu sesji (ang. _STEK - Session Ticket Encryption Key_) i wyśle go do klienta. Klient przechowuje ten zaszyfrowany klucz sesji, zwany biletem, wraz z odpowiednim kluczem sesji. Serwer tym samym zapomina o kliencie, umożliwiając wdrożenia bezstanowe.

Przy kolejnym połączeniu, klient wysyła bilet wraz z parametrami początkowymi. Jeśli serwer nadal ma klucz szyfrowania biletu sesji, odszyfruje go, wyodrębni klucz sesji i zacznie go używać. Ustanawia to wznowione połączenie i oszczędza komunikację w obie strony, pomijając kluczowe (początkowe) negocjacje. W przeciwnym razie klient i serwer powrócą do normalnego uzgadniania. Widzimy, że cała dodatkowa obsługa odbywa się po stronie klienta.

Co kluczowe i warte zapamiętania, bilety sesji zawierają klucze sesji oryginalnego połączenia, więc skompromitowany bilet sesji pozwala atakującemu odszyfrować nie tylko wznowione połączenie, ale także oryginalne połączenie (problem nasila się, gdy sesja jest regularnie wznawiana, a te same klucze sesji są ponownie pakowane w nowe bilety sesji). Niestety większość serwerów nie usuwa kluczy sesji ani biletów, zwiększając w ten sposób ryzyko wycieku danych z poprzednich (i przyszłych) połączeń. Co więcej, takie zachowanie „niszczy” tajemnicę przekazywania (ang. _Forward Secrecy_), która chroni poufność połączeń na wypadek, gdyby serwer został naruszony przez atakującego, nawet po upływie okresu ważności biletu sesyjnego. Wznawianie połączeń bez wykonania żadnej wymiany kluczy (tym samym bez zaoferowania tajemnicy przekazywania) jest jednym z większych problemów (i niejedynym co zaraz zobaczysz) związanym z biletami sesji w TLSv1.2.

Niestety, moim zdaniem, niektóre implementacje pozostawiają wiele do życzenia, powodując, że jest to jeden z najsłabszych elementów protokołu TLS. Dokładniej problem opisano w świetnym artykule [How to botch TLS forward secrecy](https://www.imperialviolet.org/2013/06/27/botchingpfs.html) a dowodem na problemy z mechanizmem i implementacjami tego mechanizmu niech będzie najnowsza podatność oznaczona jako [CVE-2020-13777](https://www.gnutls.org/security-new.html#GNUTLS-SA-2020-06-03) odkryta w bibliotece GnuTLS. Szkopuł polegał na tym, że mechanizm rotacji kluczy w rzeczywistości w ogóle nie działa a zmiana, która miała pomóc w zachowaniu tajemnicy przekazywania i wprowadziła tę lukę, zwiększyła tylko złożoność. W konsekwencji możliwe było pasywne rozszyfrowanie większość wersji od TLSv1.0 do TLSv1.2 oraz przechwycenie większość połączeń wykorzystujących najnowszą wersję protokołu, tj. TLSv1.3 (więcej szczegółów tutaj: [CVE-2020-13777: TLS 1.3 session resumption works without master key, allowing MITM](https://gitlab.com/gnutls/gnutls/-/issues/1011)).

Problem kluczy sesji dotyczy tak naprawdę ich obecnej implementacji (inżynierowie serwera NGINX zalecali ich wyłączenie ze względu na brak odpowiednich mechanizmów odpowiedzialnych za rotację kluczy), a nie tego, że sam mechanizm jest niebezpieczny czy w jakiś sposób podatny (nie do końca jest to prawda, o czym się zaraz przekonasz). Po pierwsze, włączając go, nie zapewnisz poufności przekazywania i spowodujesz, że PFS będzie bezużyteczny, ponieważ przy korzystaniu z mechanizmu biletów sesji, wszystkie klucze szyfrowania będą ostatecznie szyfrowane tylko jednym kluczem szyfrowania, tj. kluczem biletu sesji. Moim zdaniem, bilety sesji nie powinny być w ogóle wykorzystywane z jeszcze jednego powodu: dla wersji TLSv1.2 i niższych, ujawnia się ich największa wada — są one wysyłane w czystej postaci na początku pierwotnego połączenia (identyfikatory sesji i bilety sesji zostały usunięte z TLSv1.3, więcej do poczytania w artykule [The future of session resumption - Forward secure PSK key agreement in TLS 1.3](https://timtaubert.de/blog/2017/02/the-future-of-session-resumption/)]). Na poniższym zrzucie widać, że wiadomość <span class="h-b">NewSessionTicket</span> jest wysyłana z serwera do klienta przed wiadomością <span class="h-b">ChangeCipherSpec</span>:

<p align="center">
  <img src="/assets/img/posts/tls_and_session_tickets.png">
</p>

Inny problem z obecnymi implementacjami to usuwanie informacji o sesjach. Uważam, że jedynym sposobem na prawdziwe usunięcie danych sesyjnych jest zastąpienie ich nową sesją — czyli odpowiednia rotacja w celu ich zniszczenia. Idealną praktyką jest generowanie losowych kluczy biletów sesji oraz ich częsta wymiana. Ciekawostka: na przykład Twitter rotuje klucze co 12h, zaś stare usuwa co 36h. W ramach poszerzenia swojej wiedzy polecam także zapoznać się z niezwykle interesującą pracą [Measuring the Security Harm of TLS Crypto Shortcut]({{ site.url }}/assets/pdfs/forward-secrecy-imc16.pdf) <sup>[PDF]</sup>. Warto wiedzieć, że TLSv1.3 rozwiązuje w pewien sposób problem rotacji, zaprzęgając do tego klucze Diffie-Hellman (więcej informacji uzyskasz w artykule [How to botch TLS forward secrecy](https://www.imperialviolet.org/2013/06/27/botchingpfs.html)). Koniecznie zapoznaj się także ze świetnym opisem dotyczącym [implementacji sesji po stronie serwerów TLS](https://timtaubert.de/blog/2014/11/the-sad-state-of-server-side-tls-session-resumption-implementations/).

Jeśli zdecydujesz się na włączenie biletów sesji, NGINX powinien wygenerować losowy klucz podczas uruchamiania i trzymać go w pamięci (ponadto odpowiednio nim zarządzać czego tak naprawdę nie robi). W ramach alternatywy, bilety sesji mogą być szyfrowane i deszyfrowane za pomocą tajnego klucza określonego jako plik za pomocą dyrektywy `ssl_session_ticket_key` (musi on zawierać 80 (do szyfrowania używany jest AES256) lub 48 (do szyfrowania używany jest AES128) bajtów losowych danych). W tym przypadku musisz pamiętać, aby odpowiednio „obracać” kluczem tak, by zapewnić mechanizm automatycznego odnawiania (np. restartując serwer co jakiś czas, co jednak nie zawsze rozwiązuje problem). Co więcej, należy rozważyć przeniesienie tych kluczy do pamięci (wykorzystując np. <span class="h-b">tmpfs</span>), jednak moim zdaniem rodzi to zbyt wiele komplikacji związanych z zarządzaniem.

  > [Vincent Bernat](https://vincent.bernat.ch/en) napisał świetne [narzędzie](https://github.com/vincentbernat/rfc5077/blob/master/rfc5077-client.c) do testowania mechanizmu wznawiania sesji z wykorzystaniem ticket'ów.

Jeśli twoje serwery mają wystarczającą moc, możesz rozważyć całkowite wyłączenie identyfikatorów sesji i biletów sesji. Według mnie jest to nadal zalecane rozwiązanie, aby zapewnić tajemnicę przekazywania, ponieważ większość używanych serwerów HTTP (Apache, NGINX) nie obsługuje odpowiedniej rotacji tych parametrów.

Przykład konfiguracji:

```nginx
# context: http, server
# default: on
ssl_session_tickets off;
```

Oficjalna dokumentacja: [ssl_session_tickets](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_session_tickets).

## ssl_buffer_size

Parametr ten odpowiada za kontrolę rozmiaru rekordu (za rozmiar bufora) przesyłanych danych za pomocą protokołu TLS. Klient może odszyfrować dane dopiero po otrzymaniu pełnego rekordu, zaś jego rozmiar może mieć znaczący wpływ na wydajność aplikacji w czasie ładowania strony. Jest to jeden z tych parametrów, dla którego spotkać można różne wartości i wyciągnąć wniosek, że idealny rozmiar nie istnieje. Spowodowane jest to pewną niejednoznacznością oraz problemami występującymi w sieci, która wykorzystuje protokół TCP.

Aby dostosować wartość tego parametru, należy pamiętać m.in. o rezerwacji miejsca na różne opcje TCP (znaczniki czasu, skalowanie okna czy opcje selektywnego potwierdzania, tj. [SACK](https://www.icir.org/floyd/sacks.html)), które mogą zajmować do 40 bajtów. Uwzględnić należy także rozmiar rekordów TLS (pamiętaj, że uścisk dłoni jest pełen małych pakietów), który zmienia się w zależności od wynegocjowanego szyfru między klientem a serwerem (średnio od 20 do 60 bajtów jako narzut protokołu TLS). Istotne jest także to, że przeglądarka (klient) może korzystać z danych dopiero po całkowitym otrzymaniu rekordu TLS, stąd wartość tego parametru powinna być mniej więcej taka, jak rozmiar segmentu TCP.

Tym samym można przyjąć: <span class="h-b">1500 bajtów (MTU) - 40 bajtów (IP) - 20 bajtów (TCP) - 60-100 bajtów (narzut TLS) ~= 1300 bajtów</span>.

  > Ciekawostka: jeżeli sprawdzisz rekordy zwracane przez serwery Google, zobaczysz, że zawierają one ok. 1300 bajtów danych.

Spakowanie każdego rekordu TLS do dedykowanego pakietu powoduje dodatkowe obciążenie związane z tworzeniem ramek i prawdopodobnie zajdzie potrzeba ustawienia większych rozmiarów rekordów (większy rozmiar rekordu optymalizuje przepustowość), jeśli przesyłasz strumieniowo większe (i mniej wrażliwe na opóźnienia) dane.

Jednak im większy rozmiar rekordu TLS, tym większe prawdopodobieństwo, że możemy ponieść dodatkowy koszt z powodu retransmisji TCP lub „przepełnienia” okna TCP (ang. _TCP congestion window_). Rozwiązanie jest w miarę proste i polega na wysyłaniu mniejszych rekordów tak, aby pasowały do jednego segmentu TCP. Jeśli okno przeciążenia TCP jest małe, tj. podczas powolnego startu sesji (ang. _TCP Slow Start_) lub jeśli wysyłamy interaktywne dane, które powinny zostać przetworzone jak najszybciej (czyli większość ruchu HTTP), wówczas mały rozmiar rekordu pomaga zmniejszyć kosztowne opóźnienie związane z opóźnieniami jeszcze innej warstwy buforowania.

W dokumentacji serwera NGINX jest następujące zalecenie:

<p class="ext">
  <em>
    By default, the buffer size is 16k, which corresponds to minimal overhead when sending big responses. To minimize Time To First Byte it may be beneficial to use smaller values, for example: ssl_buffer_size 4k;
  </em>
</p>

Myślę jednak, że w przypadku stałego rozmiaru, optymalną wartością jest wartość 1400 bajtów (lub bardzo zbliżona). 1400 bajtów (tak naprawdę powinno być nawet nieco niższe zgodnie z wcześniej zaprezentowanym równaniem) jest zalecanym ustawieniem dla ruchu interaktywnego, w którym głównie chodzi o uniknięcie niepotrzebnych opóźnień spowodowanych utratą/fluktuacją fragmentów rekordu TLS.

Spójrzmy także na poniższą rekomendację (wydaje mi się, że autorami są Leif Hedstrom, Thomas Jackson oraz Brian Geffon, niestety nie mogę znaleźć jej źródła):

- mniejszy rozmiar rekordu TLS = <span class="h-b">MTU/MSS (1500) - TCP (20 bytes) - IP (40 bytes): 1500 - 40 - 20 = 1440 bytes</span>
- większy rozmiar rekordu TLS = maksymalny rozmiar wynosi <span class="h-b">16,383 (2^14 - 1)</span>

Przykład konfiguracji:

```nginx
# context: http, server
# default: 16k
ssl_buffer_size 1400;
```

Oficjalna dokumentacja: [ssl_buffer_size](http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_buffer_size).

## TLS Dynamic Record Sizing

Na koniec pomówmy jeszcze o jednej bardzo istotnej kwestii, mianowicie o dynamicznym rozmiarze rekordu TLS, który może mieć (niekiedy znaczący, innym razem bardzo delikatny) wpływ na wydajność połączenia, pozwalając najskuteczniej współdziałać z protokołami warstw niższych, takimi jak TCP. W najgorszym wypadku, który niestety jest obecnie dosyć częstą sytuacją występującą w sieci, nieoptymalny rozmiar rekordu może opóźnić przetwarzanie otrzymanych danych. Na przykład, w sieciach komórkowych może to przełożyć się na setki milisekund niepotrzebnego opóźnienia.

Stały rozmiar bufora ma niestety pewne wady i są one ściśle związane z warstwową budową sieci. Rekord TLS zwykle ma rozmiar 16 KB, co może powodować problemy, gdy implementacje próbują dopasować rekord TLS o takim rozmiarze do ładunków protokołu warstwy znajdującej się niżej. Niestety, segmenty TCP i rekordy TLS najczęściej nie są tego samego rozmiaru. Dzieje się tak, ponieważ protokół TLS dzieli przesyłane dane na rekordy o ustalonym (maksymalnym) rozmiarze (w NGINX odpowiada za to parametr `ssl_buffer_size`), a następnie przekazuje te rekordy do protokołu TCP, który występuje w warstwie niżej. TCP natychmiast dzieli te rekordy na segmenty, które są następnie przesyłane. Ostatecznie segmenty te są wysyłane w pakietach IP, które przemierzają sieci lokalne i Internet.

Aby zapobiec zatorom w sieci i zapewnić niezawodne dostarczanie danych, TCP wyśle ​​tylko ograniczoną liczbę segmentów przed oczekiwaniem na potwierdzenie ich odebrania przez drugą stronę komunikacji. Ponadto protokół TCP gwarantuje, że segmenty są dostarczane do aplikacji stąd jeśli pakiet zagubi się gdzieś między nadawcą a odbiorcą, najprawdopodobniej reszta segmentów zostanie zatrzymana w buforze, czekając na przesłanie brakującego segmentu, zanim bufor zostanie zwolniony do aplikacji.

Jednak w przypadku protokołu TLS mamy dodatkową warstwę buforowania ze względu na kontrole integralności. Gdy TCP dostarczy pakiety do warstwy TLS, która jest nad nim, musimy najpierw zgromadzić cały rekord, a następnie zweryfikować jego sumę kontrolną MAC i tylko wtedy, gdy się to powiedzie, możemy zwolnić dane do aplikacji, która jest w warstwie wyżej. W rezultacie, jeśli serwer emituje dane w porcjach po 16 KB, odbiorca musi również odczytywać dane o takim rozmiarze.

  > Innymi słowy, nawet jeśli odbiorca ma 15 kilobajtów rekordu w buforze i czeka na ostatni pakiet, aby ukończyć 16 kilobajtowy rekord, aplikacja nie może go odczytać, dopóki cały rekord nie zostanie odebrany i nie zostanie obliczona i zweryfikowana suma kontrolna - w tym leży główny problem jeśli chodzi o opóźnienia.

Jak już pewnie zauważyłeś, cierpią na tym najbardziej protokoły znajdujące nad protokołem TCP, tj. HTTP oraz TLS, ponieważ wraz ze wzrostem współczynnika utraty pakietów działają one coraz gorzej. Protokół HTTP/2 rozwiązuje po części problem poprzez multipleksowanie, jednak sumarycznie i tak to nic nie daje, ponieważ używa TCP jako transportu, więc wszystkie jego strumienie mogą być blokowane, gdy utracony zostanie pojedynczy pakiet TCP. Taka sytuacja jest określona jako blokowanie na początku linii (ang. _TCP head of line blocking_), której chyba idealnym rozwiązaniem byłoby uruchomienie HTTP/2 przez UDP. Sytuacja pogarsza się, im gorszej jakości sieć jest wykorzystywana (utrata choćby 2% pakietów, świadczy o bardzo niskiej, wręcz tragicznej jakości sieci). Jeden utracony pakiet w strumieniu TCP powoduje, że wszystkie strumienie czekają, aż pakiet zostanie ponownie przesłany i odebrany. Widzimy tym samym, że nakładanie się warstw TLS na TCP może powodować opóźnienia w dostarczaniu wiadomości.

  > Dla TLS oznacza to, że duży rekord podzielony na wiele segmentów TCP może napotkać nieoczekiwane opóźnienia. TLS może obsłużyć tylko pełne rekordy, dlatego brak segmentu TCP opóźnia cały rekord TLS i w konsekwencji całą komunikację. W przypadku parametru `ssl_buffer_size` i jednoczesnym wykorzystaniu protokołu HTTP/2 warto rozważyć modyfikację dyrektywy `http2_chunk_size`, która ustawia maksymalny rozmiar fragmentów, na które jest pocięte ciało odpowiedzi (myślę, że powinna ona być dostosowywana w zależności od wartości rekordu TLS tak, aby fragment HTTP2 zmieścił się w rekordzie TLS). Zbyt niska wartość spowoduje wyższe koszty ogólne, zaś zbyt wysoka, utrudni ustalanie priorytetów z powodu _head of line blocking_.

Statyczny rozmiar rekordu wprowadza kompromis między opóźnieniem a przepustowością - mniejsze rekordy są dobre dla opóźnienia, ale szkodzą przepustowości i obciążeniu procesora. Małe rekordy powodują nadmierne obciążenia, duże rekordy powodują zwiększone opóźnienia — nie ma jednej wartości dla optymalnego rozmiaru rekordu. Zamiast tego w przypadku aplikacji internetowych najlepszą strategią jest dynamiczne dostosowywanie jego rozmiaru (tak, aby uzyskać najlepszą wydajność) w zależności od stanu połączenia TCP.

Dynamiczne rozmiary rekordów skalowane w zależności od stanu połączenia TLS, eliminują tak naprawdę dwa istotne problemy:

- korzystanie z rekordu wielkości pakietu gwarantuje, że dostarczamy najlepszy pierwszy bajt danych wysłanych przez serwer (ang. _TTFB - Time to first byte_)
- minimalizuje koszty ogólne procesora (po stronie klienta i serwera) w przypadku mniejszych rekordów

Ogólnie rzecz biorąc, ma to na celu optymalizację przyrostowego dostarczania małych plików, a także w przypadku dużych pobrań, w których priorytetem jest ogólna przepustowość.

W idealnym scenariuszu sytuacja powinna wyglądać tak:

- nowe połączenia domyślnie mają mały rozmiar rekordu
- każdy rekord mieści się w pakiecie TCP
- pakiety są opróżniane na granicach rekordów
- serwer śledzi liczbę zapisanych bajtów od czasu resetu i znacznik czasu ostatniego zapisu
- jeśli zapisano pewien próg danych (zastosowana strategia polega zasadniczo na użyciu małych rekordów TLS, które pasują do jednego segmentu TCP dla pierwszych ~1MB danych), to zwiększ rozmiar rekordu do 16 KB
- jeśli znacznik czasu ostatniego zapisu został przekroczony, zresetuj licznik wysłanych danych

W celu rozwiązania tych problemów, inżynierowie Cloudflare stworzyli [poprawkę](https://github.com/cloudflare/sslconfig/blob/master/patches/nginx__dynamic_tls_records.patch) domyślnego mechanizmu, która dodaje obsługę dynamicznego rozmiaru rekordów TLS (wprowadza inteligentniejszą strategię) w serwerze NGINX (dostępna jest ona np. we FreeBSD jako jedna z opcji do wyboru podczas kompilacji).

Krótko mówiąc, umożliwia ona, aby zamiast statycznego rozmiaru bufora ustalonego z poziomu `ssl_buffer_size` (ustalony rozmiar rekordu TLS z domyślną wartością 16 KB), początkowe żądania zmieściły się w najmniejszej możliwej liczbie segmentów TCP, a następnie były zwiększane w zależności od obciążenia sieci. Rozpoczynanie od małego rozmiaru rekordu pomaga dopasować rozmiar rekordu do segmentów wysyłanych przez TCP na początku połączenia. Po uruchomieniu połączenia rozmiar rekordu można odpowiednio dostosować do panujących warunków w sieci.

Gdy połączenie jest nowe, najlepszą strategią jest zmniejszenie rozmiaru rekordu podczas wysyłania nowej serii danych. W takim przypadku, jeśli okno przeciążenia TCP jest niskie lub gdy połączenie było bezczynne przez pewien czas, każdy pakiet TCP powinien przenosić dokładnie jeden rekord TLS, a rekord TLS powinien zajmować pełny maksymalny segment (ang. _MSS - Maximum Segment Size_), równy rozmiarowi ramki Ethernetowej, tj. 1460 bajtów, przydzielany przez TCP. Gdy okno przeciążenia połączenia jest duże i jeśli przesyłamy duży strumień (np. strumieniowanie wideo), rozmiar rekordu TLS można zwiększyć, tak aby obejmował wiele segmentów TCP (do 16 KB), w celu zmniejszenia ramkowania i obciążenie procesora klienta oraz serwera.

Zasada działania tej modyfikacji jest następująca: każde połączenie rozpoczyna się od małych rekordów (`ssl_dyn_rec_size_lo` o domyślnej wartości 1369 bajtów). Dlaczego małych? Chodzi o to, aby początkowe rekordy pasowały do jednego segmentu TCP oraz by nie były blokowane (problem _TCP head of line blocking_) z powodu powolnego startu TCP. Po określonej liczbie rekordów (`ssl_dyn_rec_threshold` o domyślnej wartości 40) rozpoczyna się zwiększanie ich rozmiaru (aby zmniejszyć obciążenie nagłówka; co więcej jesteśmy w stanie uniknąć blokowania HoL pierwszego bajtu). Wniosek z tego taki, że po 41 rekordach, czyli przesłaniu 54 KB (41 x 1369 bajtów = 56 129 bajtów) rozpoczyna się wysyłanie rekordów o wartość odpowiednio zmodyfikowanej do wartości 4229 bajtów (`ssl_dyn_rec_size_hi`), czyli trzykrotnie (do 3 pakietów TCP). Następnie po kolejnych 40 rekordach, czyli przesłaniu 165 KB (40 x 4229 = 169 160 bajtów), wartość jest ponownie zwiększana tym razem do maksymalnego rozmiaru bufora (`ssl_buffer_size`), czyli jego domyślnej wartości 16384 bajtów.

  > Powyższe można zobrazować tak: zacznij od małej wielkości rekordu, aby zoptymalizować dostarczanie małych/interaktywnych danych (większość ruchu HTTP). Następnie, jeśli przesyłany jest duży plik, zwiększ rozmiar rekordu do 16 KB i kontynuuj korzystanie z niego, dopóki połączenie nie przestanie działać. Po wznowieniu komunikacji zacznij ponownie od małego rozmiaru rekordu.

Co więcej, jeśli połączenie pozostaje bezczynne przez czas dłuższy niż ten określony za pomocą zmiennej `ssl_dyn_rec_timeout` (domyślnie 1s), rozmiar rekordu TLS jest zmniejszony do `ssl_dyn_rec_size_lo` i cała logika jest powtarzana (rozpoczyna się ponownie od małych rekordów). Jeśli wartość `ssl_dyn_red_timeout` jest ustawiona na 0, wówczas dynamiczne rozmiary rekordów TLS są wyłączone (całym mechanizmem możemy sterować również za pomocą `ssl_dyn_rec_enable` gdzie wartość <span class="h-b">off</span> go wyłącza, a <span class="h-b">on</span> włącza) i zamiast tego zostanie użyty stały rozmiar określony za pomocą `ssl_buffer_size`.

<p align="center">
  <img src="/assets/img/posts/tls_dynamic_records.png">
</p>

Domyślna wartość rozmiaru początkowych rekordów, tj. 1369 bajtów została zaprojektowana, aby zmieścić cały rekord w jednym segmencie TCP (TLS + IPv6 w jednym segmencie TCP dla małych rekordów i 3 segmentach dla dużych rekordów): <span class="h-b">1500 bajtów (MTU) - 20 bajtów (TCP) - 40 bajtów (IP) - 10 bajtów (znaczniki czasu) - 61 (maksymalne obciążenie/narzut TLS) = 1369 bajtów</span>. Narzut TLS zmienia się w zależności od wybranego szyfru (zerknij na drafty: [Overview and Analysis of Overhead Caused by TLS - 3.2. Traffic Overhead](https://tools.ietf.org/id/draft-mattsson-uta-tls-overhead-01.html#rfc.section.3.2) <sup>[IETF]</sup> oraz [Record Size Limit Extension for Transport Layer Security (TLS)](https://tools.ietf.org/id/draft-ietf-tls-record-limit-01.html) <sup>[IETF]</sup>), jednak każdy rekord doda od 20 do 40 bajtów narzutu dla nagłówka, MAC czy opcjonalnego wypełnienia. Moim zdaniem, jest tutaj pewna wada, mianowicie wartości `ssl_dyn_rec_size_lo/ssl_dyn_rec_size_hi` powinny być automatycznie dostosowywane na podstawie używanego szyfru, ponieważ różne szyfry mają różne maksymalne rozmiary rekordów TLS (<span class="h-b">GCM/CHACHA-POLY</span> np. ma tylko 29 bajtów narzutu co stanowi ok. połowę z 61 bajtów z powyższego obliczenia).

Zwiększenie rozmiaru rekordu do jego maksymalnego rozmiaru (16 KB) niekoniecznie jest dobrym pomysłem, jednak należy też pamiętać, że im mniejszy rekord, tym wyższe koszty ramkowania. Jeśli rekord obejmuje wiele pakietów TCP, wówczas warstwa TLS musi poczekać, aż wszystkie pakiety TCP dotrą do miejsca docelowego, zanim będzie mogła odszyfrować dane. Jeśli którykolwiek z tych pakietów TCP zostanie zgubiony, nastąpi zmiana ich kolejności lub będzie dławiony z powodu kontroli przeciążenia, poszczególne fragmenty rekordu TLS będą musiały zostać buforowane przed dekodowaniem, co spowoduje dodatkowe opóźnienie. W praktyce opóźnienia te mogą powodować znaczne wąskie gardła dla przeglądarki, która woli pobierać dane w sposób strumieniowy.

Co istotne, poprawka jest w pełni konfigurowalna z poziomu kontekstu `http {...}` serwera NGINX. Odpowiadają za to następujące dyrektywy zdefiniowane w pliku `src/http/modules/ngx_http_ssl_module.c`:

```c
{ ngx_string("ssl_dyn_rec_enable"),
  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
  ngx_conf_set_flag_slot,
  NGX_HTTP_SRV_CONF_OFFSET,
  offsetof(ngx_http_ssl_srv_conf_t, dyn_rec_enable),
  NULL },

{ ngx_string("ssl_dyn_rec_timeout"),
  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
  ngx_conf_set_msec_slot,
  NGX_HTTP_SRV_CONF_OFFSET,
  offsetof(ngx_http_ssl_srv_conf_t, dyn_rec_timeout),
  NULL },

{ ngx_string("ssl_dyn_rec_size_lo"),
  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
  ngx_conf_set_size_slot,
  NGX_HTTP_SRV_CONF_OFFSET,
  offsetof(ngx_http_ssl_srv_conf_t, dyn_rec_size_lo),
  NULL },

{ ngx_string("ssl_dyn_rec_size_hi"),
  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
  ngx_conf_set_size_slot,
  NGX_HTTP_SRV_CONF_OFFSET,
  offsetof(ngx_http_ssl_srv_conf_t, dyn_rec_size_hi),
  NULL },

{ ngx_string("ssl_dyn_rec_threshold"),
  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
  ngx_conf_set_num_slot,
  NGX_HTTP_SRV_CONF_OFFSET,
  offsetof(ngx_http_ssl_srv_conf_t, dyn_rec_threshold),
  NULL },
```

Poniżej znajdują się domyślne wartości każdego z parametrów:

- `ssl_dyn_rec_enable off;`
- `ssl_dyn_rec_timeout 1000;` (ms) = 1s
- `ssl_dyn_rec_size_lo 1369;` (bytes) = ~1KB
- `ssl_dyn_rec_size_hi 4229;` (bytes) = ~4KB
- `ssl_dyn_rec_threshold 40;`

Poprawkę można pobrać z [oficjalnego repozytorium](https://raw.githubusercontent.com/cloudflare/sslconfig/master/patches/nginx__dynamic_tls_records.patch) oraz zaaplikować ręcznie, w tym celu należy wykonać:

```bash
git clone https://github.com/nginx/nginx
cd nginx/

patch -p1 < nginx__dynamic_tls_records.patch
```

Ogólny wniosek jest taki, że lepiej nie używać ustalonego rozmiaru rekordu TLS, ale dostosować jego rozmiar w trakcie połączenia (zwiększać w przypadku braku zatorów w sieci i zmniejszać w przypadku przeciążenia). Głównym celem jest zminimalizowanie prawdopodobieństwa buforowania w warstwie aplikacji z powodu utraconych pakietów, zmian kolejności pakietów oraz retransmisji. Wszystko to zapewnia najlepszą wydajność dla ruchu interaktywnego (jednak korzyści mogą się różnić w zależności od wielu czynników).

W celu pełnego zrozumienia opisywanego problemu polecam przeczytać książkę [High Performance Browser Networking](https://hpbn.co/) (autor: Ilya Grigorik) oraz w szczególności rozdział [Optimizing for TLS - Optimize TLS Record Size](https://hpbn.co/transport-layer-security-tls/#optimize-tls-record-size) a także artykuł tego samego autora [Optimizing TLS Record Size & Buffering Latency](https://www.igvita.com/2013/10/24/optimizing-tls-record-size-and-buffering-latency/).

Na koniec, warto jeszcze pamiętać o ew. dostrojeniu parametrów jądra i przeprowadzeniu testów po wprowadzeniu poprawki, w tym testów porównujących wydajność połączenia wykorzystującego dynamiczną oraz stałą wartość rozmiaru rekordu (ustawianą za pomocą parametru `ssl_buffer_size` tj. zalecaną 4 kilobajty).
