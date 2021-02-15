---
layout: post
title: "NGINX: Blokowanie nieprawidłowych wartości nagłówka Referer"
description: "Wpis o tym, dlaczego tak ważne jest blokowanie nieprawidłowych wartości nagłówka Referer."
date: 2021-02-14 23:24:45
categories: [nginx]
tags: [http, nginx, best-practices, server-name, referer]
comments: true
favorite: false
toc: true
new: true
---

W tym wpisie chciałbym przedstawić sposób na blokowanie żądań zawierających niepożądany nagłówek `Referer`. Głównie chodzi o to, aby ​​treść ładowana było tylko z autoryzowanych domen, a każde nieautoryzowane żądanie rzucało odpowiedzią z kodem 403.

## Czym jest referer?

Nagłówek `Referer` jest opcjonalnym nagłówkiem żądania protokołu HTTP przechowującym adres poprzedniej strony internetowej, która jest połączona z bieżącą witryną lub żądanym zasobem. Został on zdefiniowany w [RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1 - 14.36 Referer](https://tools.ietf.org/html/rfc2616#section-14.36) <sup>IETF</sup> oraz [RFC 7231 - Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content](https://tools.ietf.org/html/rfc7231#section-5.5.2) <sup>IETF</sup>.

Mówiąc prościej, nagłówek ten zawiera adres strony wysyłającej żądanie (wkazuje źródło lub adres URL strony internetowej, z której wykonano żądanie). Na przykład, gdy jedna witryna internetowa łączy się z inną witryną, pierwsza z nich odsyła użytkownika do drugiej. Zazwyczaj ta informacja jest przechwytywana właśnie w polu nagłówku `Referer`. Dzięki temu, po sprawdzeniu strony odsyłającej, nowa strona może zobaczyć, skąd pochodzi żądanie. Widzimy, że umożliwia on serwerom identyfikację, skąd pochodzą żądania (a tym samym klienci odwiedzają strony na które wchodzą), i mogą używać tych danych na przykład do analiz, rejestrowania lub optymalizacji.

<p align="center">
  <img src="/assets/img/posts/referer_example.png">
</p>

Zgodnie z [Mozilla Web technology for developers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer), gdy podążasz za linkiem, nagłówek ten przechowywać będzie adres URL strony zawierającej łącze. Gdy wyślesz żądania AJAX do innej domeny, nagłówke `Referer` zawierał będzie adres URL Twojej strony. W najczęstszej sytuacji oznacza to, że gdy użytkownik kliknie hiperłącze w przeglądarce internetowej, przeglądarka wysyła żądanie do serwera, na którym znajduje się docelowa strona internetowa. Żądanie może zawierać pole `Referer`, które wskazuje ostatnią stronę, na której był użytkownik (tę, na której kliknął link).

Idąc za RFC 2616 składnia nagłówka `Referer` jest następująca:

```
Referer = "Referer" ":" ( absoluteURI | relativeURI )
```

Mówiąc prościej, jego forma wygląda najczęściej tak (`Referer: <url>`):

```
Referer: https://www.google.com/
```

## Czy użycie tego nagłówka jest bezpieczne?

Dochodzimy do głównego problemu. Chociaż nagłówek `Referer` ma wiele niewinnych zastosowań, jego użycie zwiększa ryzyko naruszenia prywatności i bezpieczeństwa w kontekście danej strony.

Na przykład, jeśli zezwolisz witrynie <span class="h-b">foo.bar.com</span> na pobieranie zasobów z domeny <span class="h-b">example.com</span>, użytkownicy będą mogli kliknąć łącze <span class="h-b">example.com</span> w witrynie <span class="h-b">foo.bar.com</span> i przejść do tej strony. Niestety, bez odpowiednich reguł filtrujących każdy będzie mógł połączyć się z Twoją stroną. Jeśli atakujący umieści na spreparowanej stronie znajdującej się pod domeną <span class="h-b">examplle.com</span> odwołania do <span class="h-b">static.example.com</span>, będzie w stanie serwować wszystkie statyczne zasoby z Twojej domeny.

  > W przypadku elementów takich jak obrazki lub reklamy, punktem odniesienia jest zazwyczaj strona, która wywołuje te elementy.

Należy pamiętać, że sfabrykowanie żądania z odpowiednią wartością pola nagłówka `Referer` jest dość łatwe. Istnieją jednak bardziej problematyczne zastosowania, takie jak śledzenie lub kradzież informacji, a nawet nieumyślne ujawnienie poufnych informacji. Problemy nasilają się, kiedy pełny adres URL zawierający ścieżkę i ciąg zapytania jest wysyłany między źródłami. Może to stanowić niezwykle poważne zagrożenie dla bezpieczeństwa:

<p align="center">
  <img src="/assets/img/posts/referer_security_issues.png">
</p>

Zgodnie z [Mozilla - Referer header: privacy and security concerns](https://developer.mozilla.org/en-US/docs/Web/Security/Referer_header:_privacy_and_security_concerns) weźmy na przykład stronę „resetowania hasła” z linkiem do mediów społecznościowych w stopce. Jeśli skorzystano z odsyłacza, w zależności od tego, w jaki sposób udostępniono informacje, witryna mediów społecznościowych może otrzymać adres URL resetowania hasła i nadal może korzystać z udostępnionych informacji, potencjalnie narażając bezpieczeństwo użytkownika. Zgodnie z tą samą logiką obraz przechowywany na stronie trzeciej, ale osadzony na Twojej stronie może spowodować ujawnienie poufnych informacji stronie trzeciej. Nawet jeśli bezpieczeństwo nie jest zagrożone, informacje mogą nie być czymś, co użytkownik chce udostępniać.

### W jaki sposób poprawić bezpieczeństwo?

Główną ideą powinno być masowe blokowanie żądań. Jesteśmy w stanie wykonać to z poziomu serwera NGINX. Należy wykorzystać do tego moduł [ngx_http_referer_module](http://nginx.org/en/docs/http/ngx_http_referer_module.html). Konfiguracja wygląda jak poniżej (umieszczamy ją w kontekście `server {...}`):

```
server_name static.example.com;

valid_referers none blocked server_names example.com *.example.com monitoring.foo.bar external-shop.eu;

if ($invalid_referer) {
  return 403;
}
```

Wyjaśnijmy teraz po koleji cały blok konfiguracji. Otóż dyrektywa `server_name` przechowuje nazwy obsługiwanych hostów wirtualnych. W naszym przykładzie jest to domena <span class="h-b">static.example.com</span> obsługująca zasoby statyczne dla domeny <span class="h-b">example.com</span>.

Dyrektywa `valid_referers` określa politykę obsługi nagłówka `Referer`. Zgodnie z dokumentacją modułu, określa ona wartości pola nagłówka żądania `Referer`, które spowodują, że osadzona zmienna `$invalid_referer` będzie miała przypisany pusty ciąg (wartość 0). W przeciwnym razie dla zmiennej zostanie ustawiona wartość 1. Co ważne, to w wyszukiwaniu dopasowania nie jest rozróżniana wielkość liter.

Jako wartości tej dyrektywy pojawiają się trzy ciągi:

- <span class="h-a">none</span> - w żądaniu brakuje nagłówka `Referer`

- <span class="h-a">blocked</span> - nagłówek jest obecny w żądaniu, ale jego wartość została usunięta lub zmieniona na ciągi, które nie zaczynają się od typu protokołów takich jak HTTP czy HTTPS

- <span class="h-a">server_names</span> - nagłówek zawiera jedną z nazw wirtualnych hostów określoną z poziomu dyrektywy `server_name`

Może się wydawać, że brak nagłówka `Referer` jest czymś niepożądanym i także należałoby go blokować. Otóż nie. Brak tego nagłówka występuje gdy:

- wprowadzono adres URL witryny w samym pasku adresu przeglądarki
- odwiedzono witrynę za pomocą zakładki obsługiwanej przez przeglądarkę
- odwiedzono witrynę jako pierwszą stronę w oknie/karcie
- kliknięto łącze w zewnętrznej aplikacji
- przełączono protokół z HTTPS na HTTP
- klient znajduje się za serwerami proxy, które mogą usuwać ten nagłówek ze wszystkich żądań
- wyłączono taką możliwość z poziomu klienta (np. `curl`)
- roboty skanują Twoją witrynę


, dlatego też celem tego modułu nie jest dokładne blokowanie takich żądań, ale blokowanie masowego przepływu żądań wysyłanych przez zwykłe przeglądarki. Należy również wziąć pod uwagę, że zwykłe przeglądarki mogą nie wysyłać pola „Referer” nawet w przypadku ważnych żądań.

Domeny z symbolami wieloznacznymi są również obsługiwane (np *.example.com.). Jeśli funkcja Blokuj strony odsyłające jest włączona, strony odsyłające do linii zostaną umieszczone na czarnej liście, a jeśli są wyłączone, osoby odsyłające do linii zostaną umieszczone na białej liście.

Czarna lista ma kilka zalet w porównaniu z białymi listami:

Domena może zostać umieszczona na czarnej liście za pomocą zaledwie jednej strony odsyłającej do strefy.
Czarna lista nie wymaga aktualizacji, jeśli zasoby są ładowane z dodatkowej prawidłowej domeny.
Umieszczanie witryn odsyłających na białej liście może być trudne, ponieważ zasoby można ładować z wielu różnych domen. Może to spowodować nieoczekiwane 403błędy.
