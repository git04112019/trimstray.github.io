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

W tym wpisie chciałbym zaprezentować dostępny z poziomu serwera NGINX sposób na blokowanie żądań zawierających niepożądany nagłówek <span class="h-b">Referer</span>. Głównie chodzi o to, aby ​​treść ładowana była tylko z autoryzowanych domen, a każde nieautoryzowane żądanie rzucało odpowiedzi, np. z kodem 403.

## Czym jest referer?

Nagłówek <span class="h-b">Referer</span> jest opcjonalnym nagłówkiem żądania protokołu HTTP przechowującym adres poprzedniej strony internetowej, która jest połączona z bieżącą witryną lub żądanym zasobem. Został on zdefiniowany w [RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1 - 14.36 Referer](https://tools.ietf.org/html/rfc2616#section-14.36) <sup>IETF</sup> oraz [RFC 7231 - Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content](https://tools.ietf.org/html/rfc7231#section-5.5.2) <sup>IETF</sup>.

Mówiąc prościej, nagłówek ten zawiera adres strony wysyłającej żądanie (wskazuje źródło lub adres URL strony internetowej, z której wykonano żądanie). Na przykład, gdy jedna witryna internetowa łączy się z inną witryną, pierwsza z nich odsyła użytkownika do drugiej. Zazwyczaj ta informacja jest przechwytywana właśnie w polu nagłówku <span class="h-b">Referer</span>. Dzięki temu, po sprawdzeniu strony odsyłającej, nowa strona może zobaczyć, skąd pochodzi żądanie. Widzimy, że nagłówek ten umożliwia serwerom identyfikację, skąd pochodzą żądania (a tym samym skąd klienci odwiedzają strony, na które wchodzą), a także rejestrowania lub optymalizacji.

<p align="center">
  <img src="/assets/img/posts/referer_example.png">
</p>

Zgodnie z [Mozilla Web technology for developers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer), gdy podążasz za linkiem, nagłówek ten przechowywać będzie adres URL strony zawierającej łącze. Gdy wyślesz żądania AJAX do innej domeny, nagłówek <span class="h-b">Referer</span> zawierał będzie adres URL Twojej strony. W najczęstszej sytuacji oznacza to, że gdy użytkownik kliknie hiperłącze w przeglądarce internetowej, przeglądarka wysyła żądanie do serwera, na którym znajduje się docelowa strona internetowa. Żądanie może zawierać pole <span class="h-b">Referer</span>, które wskazuje ostatnią stronę, na której był użytkownik (tę, na której kliknął link).

Idąc za RFC 2616 składnia nagłówka <span class="h-b">Referer</span> jest następująca:

```
Referer = "Referer" ":" ( absoluteURI | relativeURI )
```

Mówiąc prościej, jego forma wygląda najczęściej tak (`Referer: <url>`):

```
Referer: https://www.google.com/
```

## Czy użycie tego nagłówka jest bezpieczne?

Dochodzimy do głównego problemu. Chociaż nagłówek <span class="h-b">Referer</span> ma wiele niewinnych zastosowań, jego użycie zwiększa ryzyko naruszenia prywatności i bezpieczeństwa w kontekście danej strony.

Na przykład, jeśli zezwolisz witrynie <span class="h-b">foo.bar.com</span> na pobieranie zasobów z domeny <span class="h-b">example.com</span>, użytkownicy będą mogli kliknąć łącze <span class="h-b">example.com</span> w witrynie <span class="h-b">foo.bar.com</span> i przejść do tej strony. Niestety, bez odpowiednich reguł filtrujących każdy będzie mógł połączyć się z Twoją stroną. Jeśli atakujący umieści na spreparowanej stronie znajdującej się pod domeną <span class="h-b">examplle.com</span> odwołania do <span class="h-b">static.example.com</span>, będzie w stanie serwować wszystkie statyczne zasoby z Twojej domeny.

  > W przypadku elementów takich jak obrazki lub reklamy, punktem odniesienia jest zazwyczaj strona, która wywołuje te elementy.

Należy pamiętać, że sfabrykowanie żądania z odpowiednią wartością pola nagłówka <span class="h-b">Referer</span> jest dość łatwe. Istnieją jednak bardziej problematyczne zastosowania, takie jak śledzenie lub kradzież informacji, a nawet nieumyślne ujawnienie poufnych danych. Problemy nasilają się, kiedy pełny adres URL zawierający ścieżkę i ciąg zapytania jest wysyłany między źródłami. Może to stanowić niezwykle poważne zagrożenie dla bezpieczeństwa:

<p align="center">
  <img src="/assets/img/posts/referer_security_issues.png">
</p>

Idąc za dokumentem [Mozilla - Referer header: privacy and security concerns](https://developer.mozilla.org/en-US/docs/Web/Security/Referer_header:_privacy_and_security_concerns) poważne problemy mogą pojawić się w przypadku stron umożliwiających „resetowania hasła” z linkiem do mediów społecznościowych w stopce. Jeśli skorzystano z odsyłacza, w zależności od tego, w jaki sposób udostępniono informacje, witryna mediów społecznościowych może otrzymać adres URL resetowania hasła i nadal może korzystać z udostępnionych informacji, potencjalnie narażając bezpieczeństwo użytkownika. Zgodnie z tą samą logiką obraz przechowywany na stronie trzeciej, ale osadzony na Twojej stronie może spowodować ujawnienie poufnych informacji stronie trzeciej. Nawet jeśli bezpieczeństwo nie jest zagrożone, informacje mogą nie być czymś, co użytkownik chce udostępniać.

### W jaki sposób poprawić bezpieczeństwo?

Główną ideą powinno być masowe blokowanie żądań, co jesteśmy w stanie wykonać z poziomu serwera NGINX, wykorzystując do tego moduł [ngx_http_referer_module](http://nginx.org/en/docs/http/ngx_http_referer_module.html). Konfiguracja wygląda jak poniżej i moim zdaniem dobrze jest umieścić ją w kontekście `server {...}` tak, aby chronić wszystkie zdefiniowane lokalizacje (choć zależy to oczywiście od konkretnego przypadku):

```nginx
server_name static.example.com;

valid_referers none blocked server_names example.com *.example.com monitoring.foo.bar external-shop.eu;

if ($invalid_referer) {
  return 403;
}
```

Wyjaśnijmy teraz po kolei cały blok konfiguracji. Otóż dyrektywa `server_name` przechowuje nazwy obsługiwanych hostów wirtualnych. W naszym przykładzie jest to domena <span class="h-b">static.example.com</span> obsługująca zasoby statyczne głównie dla domeny <span class="h-b">example.com</span>.

Dyrektywa `valid_referers` określa politykę obsługi nagłówka <span class="h-b">Referer</span>, a jej celem jest sprawdzenie tego nagłówka w żądaniu klienta i ewentualna odmowa dostępu na podstawie jego wartości. Zgodnie z dokumentacją modułu, określa ona wartości pola nagłówka żądania <span class="h-b">Referer</span>. Jeśli żaden z warunków nie jest spełniony, będzie miała przypisany pusty ciąg (wartość 0), w przeciwnym razie dla zmiennej zostanie ustawiona wartość 1. Co ważne, to w wyszukiwaniu dopasowania nie jest rozróżniana wielkość liter.

Jako wartości tej dyrektywy pojawiają się trzy parametry:

- <span class="h-a">none</span> - w żądaniu brakuje nagłówka <span class="h-b">Referer</span>

- <span class="h-a">blocked</span> - nagłówek jest obecny w żądaniu, ale jego wartość została usunięta lub zmieniona na ciągi, które nie zaczynają się od typu protokołów takich jak HTTP czy HTTPS

- <span class="h-a">server_names</span> - nagłówek zawiera jedną z nazw wirtualnych hostów określoną z poziomu dyrektywy `server_name`

Następnymi parametrami są dowolne ciągi, tj. domeny z symbolami wieloznacznymi (`*.example.com`) lub wyrażenia regularne (`~example.com`). W przypadku tych drugich należy uważać, ponieważ zadeklarowanie wartości z symbolem `~` może powodować pewne negatywne konsekwencje. Na przykład, jeśli pozwolimy, aby żądania mogły pochodzić z domeny `~example.com`, atakujący będzie mógł wykorzystać domenę `aaaexample.com`, która zostanie uznana za prawidłową.

Może się wydawać, że brak nagłówka <span class="h-b">Referer</span> jest czymś niepożądanym i także należałoby go blokować. Otóż nie. Brak tego nagłówka występuje na przykłady gdy:

- wprowadzono adres URL witryny w samym pasku adresu przeglądarki
- odwiedzono witrynę za pomocą zakładki obsługiwanej przez przeglądarkę
- odwiedzono witrynę jako pierwszą stronę w oknie/karcie
- kliknięto łącze w zewnętrznej aplikacji
- przełączono protokół z HTTPS na HTTP
- klient znajduje się za serwerami proxy, które mogą usuwać ten nagłówek ze wszystkich żądań
- wyłączono taką możliwość z poziomu klienta (np. `curl`)
- roboty skanują Twoją witrynę

Należy również wziąć pod uwagę, że zwykłe przeglądarki mogą nie wysyłać tego nagłówka.

Pamiętajmy, aby zawsze zweryfikować to, jak działa. Na przykład dodając do konfiguracji poniższy blok:

```nginx
server {

  server_name static.example.com;

  valid_referers none blocked server_names "testing.example.com";

  set $foo valid;
  if ($invalid_referer) {
    set $foo invalid;
  }

  location / {

      echo "invalid_referer: $foo '$invalid_referer'";

  }

  ...

}
```

Po wykonaniu kilku żądań da następujące wyniki:

| <b>REFERER</b> | <b>WYNIK</b> |
| :---        | :---:        |
| <none> | invalid_referer: valid '' |
| `testing.example.com` | invalid_referer: valid '' |
| `http://testing.example.com` | invalid_referer: valid '' |
| `https://testing.example.com` | invalid_referer: valid '' |
| `https://testing.example.coma` | **invalid_referer: invalid '1'** |
| `testing.example.coma` | invalid_referer: valid '' |
| `foo.example.com` | invalid_referer: valid '' |
| `https://ttesting.example.com` | **invalid_referer: invalid '1'** |

Widzimy, że zachowanie jest w miarę przewidywalne, jednak niepokój mogą budzić dwie sytuacje, tj. kiedy refererem są wartości <span class="h-b">foo.example.com</span> oraz <span class="h-b">testing.example.coma</span>. Wszystko przez parametr `blocked`, który NGINX zinterpretował jako wartość, która została usunięta przez jakiekolwiek mechanizmy pośredniczące. Zgodnie z dokumentacją, są to wszystkie wartości, które nie zaczynają się od `http://` lub `https://`, co ma miejsce w naszym przykładzie. Aby temu zapobiec, należy zmodyfikować dyrektywę `invalid_referers` usuwając z niej wartość `blocked`.

Pojawia się jeszcze jeden problem, o którym należy wspomnieć. Otóż może się zdarzyć, że gdzieś w konfiguracji ustawiłeś poniższy blok, wykorzystując moduł `map`, w celu blokowania niepożądanych refererów:

```nginx
map $http_referer $invalid_referer {
  hostnames;

  default                     0;
  "~*.fake\.com"              1;
}
```

Pamiętaj, że zdefiniowanie go w konfiguracji, powoduje, że z każdym żądaniem do zmiennej `invalid_referer` zostanie przypisana odpowiednia wartość, tj. 1, jeśli nagłówek <span class="h-b">Referer</span> zawiera np. ciąg `foo.fake.com` lub 0 jeśli znajduje się w nim wszystko to, co nie zostało rozpoznane jako wyrażenie `~*.fake\.com`.

Jeżeli pewnego dnia zechcesz stosować dyrektywę `valid_referers`, to zacznie ona działać nieprzewidywalnie. Stanie się tak, ponieważ wykorzystujemy już w konfiguracji zmienną `invalid_referer`, która też przechowuje wyniki ustawione na podstawie dyrektywy `valid_referers`. Moduł `map` będzie miał zawsze wyższy priorytet, więc zawsze przyjmie wartość 0, jeśli zmienna `http_referer` nie będzie przechowywać wartości podanej jako wyrażenie regularne.

Może to rodzić negatywne konsekwencje w wyniku czego dyrektywa `valid_referers` w ogóle nie zadziała, co spowoduje brak możliwości filtrowania nagłówka <span class="h-b">Referer</span>.
