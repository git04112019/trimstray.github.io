---
layout: post
title: "Certyfikat klienta vs certyfikat serwera"
description: "Wyjaśnienie różnic między certyfikatem klienta a serwera."
date: 2020-02-05 06:12:01
categories: [tls]
tags: [security, ssl, tls, certificates]
comments: true
favorite: false
toc: true
---

W tym wpisie chciałbym poruszyć kwestię dwóch rodzajów certyfikatów, tj. certyfikatu klienta oraz certyfikatu serwera, a także wyjaśnić różnice między nimi. Oba są certyfikatami cyfrowymi, opartymi na formacie <span class="h-b">X.509</span>, i co do zasady, potwierdzają zgodność oraz weryfikują tożsamość danego podmiotu (np. certyfikat serwera potwierdza tożsamość serwera).

Certyfikaty są najczęściej potrzebne, aby zabezpieczyć dane oraz zweryfikować właściciela witryny. Same w sobie zawierają wiele istotnych informacji, tj. informacje o urzędzie certyfikacji, który wydał certyfikat, podpis cyfrowy takiego urzędu, klucz publiczny czy datę ważności certyfikatu. Te informacje (tzw. pola) określają, do jakich zastosowań można użyć danego certyfikatu.

## Format X.509

Przed rozpoczęciem dalszej lektury należy wiedzieć, że oba typy certyfikatów są zdefiniowane jako format <span class="h-b">X.509</span>. Tego formatu używają certyfikaty SSL/TLS, o których w tym artykule będziemy mówić. Można tych terminów używać zamiennie, jednak należy znać różnicę.

<span class="h-b">X.509</span> jest standardem, który definiuje format certyfikatów klucza publicznego, weryfikuje tożsamość posiadacza certyfikatu i mapuje klucz publiczny na użytkownika, komputer lub usługę (np. domenę).

Certyfikaty SSL/TLS są certyfikatami <span class="h-b">X.509</span> z tzw. rozszerzonym użyciem klucza (ang. _Extended Key Usage_). Czyli rozszerzeniem, które określa cel użycia certyfikatu, np. do uwierzytelniania serwera czy uwierzytelniania klienta. W celu uzyskania bardziej szczegółowych informacji odsyłam do [RFC 5280 - Extended Key Usage](https://tools.ietf.org/html/rfc5280#section-4.2.1.12).

<p align="center">
  <img src="/assets/img/posts/extended_key_usage.png">
</p>

## Certyfikat klienta

Certyfikaty klienta, jak wskazuje nazwa, służą do identyfikacji klienta lub użytkownika (do sprawdzania jego tożsamości). Pozwalają one uwierzytelnić klienta i sprawdzić, a następnie potwierdzić jego tożsamości przed udzieleniem dostępu do serwera. Dzięki takiemu podejściu, jeśli użytkownik zażąda dostępu (np. do ssh, vpn, poczty czy strony), który ma uprawnienia i którego tożsamość została zweryfikowana, serwer wie, że rozmawia z uprawnionym podmiotem.

Użycie certyfikatu klienta rozwiązuje problem haseł, ponieważ tożsamość klienta lub użytkownika nie jest oceniana na podstawie tego, czy znają hasło, ale zależy to od używanych przez nich systemów. Czasami hasła nie są wystarczająco dobre. Często padamy ofiarą technik łamania haseł, takich jak ataki siłowe i keyloggery. Dlatego hasła nie są już wystarczające, gdy w grę wchodzą jakieś bardzo wrażliwe informacje.

Uwierzytelnianie klienta na podstawie certyfikatu jest najbardziej przydatne, gdy klient chce zademonstrować swoją tożsamość serwerowi. Ma to jednak sens dopiero wtedy, gdy certyfikat klienta został wydany klientowi przez urząd certyfikacji inny niż właściciel serwera. Jeśli sam serwer wydaje klientom certyfikaty, wówczas użycie certyfikatu klienta nie ma przewagi koncepcyjnej nad prostym uwierzytelnianiem za pomocą hasła.

<p align="center">
  <img src="/assets/img/posts/client_auth.gif">
</p>

## Certyfikat serwera

We wszystkich wersjach protokołu TLS certyfikat odgrywa bardzo specyficzną rolę: służy do walidacji nazwy hosta witryny internetowej i ułatwia utworzenie klucza sesji, który służy do ochrony przesyłanych danych. Oznacza to, że siła klucza sesji jest co najmniej tak samo ważna, jak klucz certyfikatu.

Certyfikaty serwera służą podwójnemu celowi: uwierzytelniają (potwierdzają) tożsamości serwera i zapewniają bezpieczny i szyfrowany kanał komunikacji między serwerem a łączącym się z nim klientem. Mówiąc ogólnie, ten rodzaj certyfikatu zawiera dane identyfikujące serwer, który najczęściej zostaną przedstawione podczas uzgadniania SSL/TLS. Ponadto, certyfikat serwera służy także do szyfrowania (tak naprawdę zajmuje się tym klucz publiczny), co oznacza, że wszelkie informacje wysyłane przez użytkownika na serwer są chronione przed zasięgiem wszelkich niewłaściwie zamierzonych stron trzecich.

Aby móc korzystać z takiego certyfikatu (i ogólnie być w jego posiadaniu), musi on zostać wydany przez urząd certyfikacji (ang. _certificate authority_ lub _certification authority_), który odpowiednio weryfikuje podmiot ubiegający się o taki certyfikat. W przypadku serwerów HTTP będzie to najczęściej nazwa serwera lub nazwa domeny, z którą łączy się klient.

Jedną z ważniejszych rzeczy jest to, że oprócz wielu istotnych informacji, certyfikat zawiera także klucz publiczny, który może być użyty do udowodnienia tożsamości serwera wymienionego w polu <span class="h-b">CN</span> certyfikatu. Kolejną ważną właściwością klucza zawartego w certyfikacie jest to, że może on być użyty do szyfrowania klucza sesji (klucza symetrycznego) uzgodnionego, czy inaczej mówiąc uzyskanego, dla danej sesji.

Certyfikat serwera jest najpopularniejszym typem certyfikatu <span class="h-b">X.509</span> i jest najczęściej wydawany dla nazw hostów (nazwy komputerów, takich jak <span class="h-b">x28-server</span> lub nazw domen, takich jak <span class="h-b">yoursite.com</span>).

<p align="center">
  <img src="/assets/img/posts/server_auth.gif">
</p>

## Czy oba typy certyfikatów można łączyć?

Z punktu widzenia [RFC 5280](https://tools.ietf.org/html/rfc5280) nie istnieje żadne ograniczenie na ustawienie obu rozszerzeń użycia klucza na tym samym certyfikacie.

Z punktu widzenia bezpieczeństwa nie ma również problemu z kryptografią/protokołem przy korzystaniu z tego samego certyfikatu do uwierzytelniania klienta, jak i serwera. Jednak nie przeszkadza również ich rozdzielenie, szczególnie jeśli z jakiegoś powodu później trzeba zmienić charakterystykę certyfikatów w sposób, który mógłby wpłynąć na funkcjonalność jednego z zastosowań (np. zmienić nazwę wyróżniającą, aby uwzględnić coś istotnego do autoryzacji klienta, która mogłaby przerwać autoryzację serwera).

## Jakie są różnice?

Certyfikaty serwera służą do uwierzytelniania tożsamości serwera oraz szyfrowania i deszyfrowania treści. Podczas gdy certyfikaty klienta, są wyraźnie używane do identyfikacji klienta dla odpowiedniego użytkownika, co oznacza uwierzytelnianie klienta na serwerze.

Oba typy używają infrastruktury klucza publicznego (ang. _PKI - Public Key Infrastructure_) do uwierzytelniania, jednak główną różnicą (moim zdaniem) jest to, że certyfikaty klienta nie szyfrują żadnych danych — są one instalowane wyłącznie w celu weryfikacji.

Poniżej znajduje się jednak dokładniejsze porównanie przestawiające cechy wspólne oraz różnice:

- oba typy certyfikatów bazują na infrastrukturze klucza publicznego (PKI)

- oba typy certyfikatów posiadają pola „Wystawiony dla” (ang. _Issued To_) oraz „Wydany przez” (ang. _Issued By_)

- certyfikat klienta służy do identyfikacji klienta lub użytkownika i uwierzytelnienia ich na serwerze, natomiast certyfikat serwera uwierzytelnia tożsamość serwera wobec klienta

- certyfikat klienta nie szyfruje żadnych danych, certyfikat serwera szyfruje (jest to jedna z jego głównych funkcji) w celu zachowania poufności danych

- zastosowanie certyfikatu odbywa się na podstawie tzw. identyfikatora obiektu (ang. _OID - object identifier_); dla certyfikatu klienta jest to wartość <span class="h-b">1.3.6.1.5.5.7.32</span>, natomiast dla certyfikatu serwera <span class="h-b">1.3.6.1.5.5.7.3.1</span>
