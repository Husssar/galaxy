# leakscope

En liten lokal sida som visar allt du lämnar ifrån dig vid en enda HTTP(S)-anslutning —
uppdelat på vad som läcker *passivt* (innan en rad JavaScript körts) och vad en sajt kan
*fråga efter* aktivt.

Byggd i defensivt syfte: att se siffrorna på sin egen maskin gör poängen tydligare än att höra
den beskrivas. Varje post har en rad om vad som faktiskt hjälper mot just den.

## Köra

Vill du ha allt påslaget direkt:

```bash
python3 server.py --demo --board
```

Sidan har en navigationsrad högst upp som länkar till varje avsnitt, till
tredjepartsdemon och till spårarens egen vy. Är ett läge avstängt står flaggan som
behövs i raden i stället för en länk, så inget är dolt bara för att man inte kan flaggorna.

### Flaggor

```bash
python3 server.py              # http://127.0.0.1:8088
python3 server.py --tls        # https, visar även TLS-fingeravtryck (JA3)
python3 server.py --host 0.0.0.0 --port 8088   # nåbar från telefonen i samma nät
python3 server.py --no-store   # spara inga besök till disk
python3 server.py --store /sökväg  # annan mapp för sparade besök
python3 server.py --demo       # tredjepartsdemon på 127.0.0.1, .2 och .3
python3 server.py --board      # klassrumsläge: mät unikhet över alla besökare
```

Inga beroenden utöver Pythons standardbibliotek. `--tls` genererar ett självsignerat
certifikat i `.certs/` via `openssl` — webbläsaren kommer varna, det är väntat.

Kör gärna `--tls`. TLS-delen är den intressantaste: handskakningens fingeravtryck följer med
varje anslutning, passerar oförändrat genom VPN och proxy, och går inte att ställa om.

## Vad sidan visar

**1 — Passivt.** IP och källport, varenda header, ordningen de skickas i (ett fingeravtryck i
sig), rådata precis som det gick över tråden, TLS-handskakningens JA3 med chiffersviter,
extensions, kurvor, ALPN och SNI i klartext, samt en löpande logg över vad servern hunnit
bygga upp om dig utan att fråga om något.

**2 — Aktivt.** Ett trettiotal avläsningar vilken sajt som helst kan göra utan tillstånd:
canvas- och WebGL-avtryck, ljudstackens flyttalsberäkning, installerade typsnitt och
talsyntesröster, tidszon, behörighetsmönster, lagringskvot, WebRTC-kandidater och mer.

**Hovra över en rad** för att se vad den faktiskt är och varför den läcker. Varje rad bär
dessutom en märkning för om privat läge hjälper — `ingen skillnad`, `delvis` eller `hjälper`.
Siffran högst upp på sidan sammanfattar: privat läge påverkar **1 av 28** avläsningar, och
fyra till påverkas delvis. Det är sidans tydligaste poäng, eftersom privat läge ofta antas
skydda mot allt det här. Det byter lagringsburk, inte maskin.

Texterna ligger samlade i tabellen `EXPLAIN` i [static/app.js](static/app.js), så de går att
läsa och rätta i ett svep. Siffran på startsidan räknas ur samma tabell och kan inte hamna
ur synk med märkningarna.

**3 — Spårning utan cookies.** Två demonstrationer: servern känner igen ditt sammansatta
fingeravtryck mellan omladdningar, och en ETag på en vanlig bild fungerar som ett tyst id som
överlever att du rensar cookies.

**4 — Jämför webbläsare.** Varje anslutning sparas automatiskt — ingen knapp att trycka på.
Öppna bara sidan i en annan webbläsare, eller i privat läge, så dyker den upp. Sidan ställer de
två senast aktiva mot varandra automatiskt. Namnet gissas ur User-Agent och går att döpa om.

Jämförelsen delar skillnaderna i två högar, och det är hela poängen med vyn:

- **Stabila attribut** som skiljer — sådant en sajt faktiskt kan spåra på.
- **Instabila attribut** som skiljer — klockavvikelse, fönsterstorlek, lagringskvot. De varierar
  även mellan två laddningar i *samma* webbläsare och duger inte att spåra på. Utan den
  uppdelningen ser privat läge ut att ändra något, fast det inte gör det.

Typiska utfall:

| Jämförelse | Vad du ser |
| --- | --- |
| Firefox mot Firefox privat | Samma fingeravtryck, noll stabila skillnader |
| Firefox mot Brave | Många stabila skillnader |
| Brave mot Brave privat | Canvas, WebGL och ljud skiljer — Brave randomiserar per session |

### Lagring

Besök sparas som en JSON-fil per besök i mappen `visits/`. En fil per besök i stället för en stor
`visits.json` betyder att en skrivning kostar lika mycket oavsett hur många besök som finns —
vilket spelar roll nu när det sker vid varje sidladdning i stället för på knapptryck.

Hopslagningen nycklas på det gissade namnet plus en handfull kärnattribut (User-Agent, skärm,
tidszon, plattform, GPU). Två saker avgjorde det valet:

- **Inte bara fingeravtrycket.** Firefox och Firefox i privat läge har *samma* avtryck — det är
  sidans poäng. Nycklade jag på avtrycket skulle de slås ihop och lärdomen försvinna.
- **Inte hela fingeravtrycket.** En enskild avläsning kan slå i tidsgränsen, och då skulle
  identiteten forka sig till en ny rad vid nästa laddning. Kärnattributen fallerar aldrig.

Av samma skäl normaliseras misslyckade avläsningar innan de går in i fingeravtrycket, och de
bidrar inte med någon entropi. Ett API som ibland svarar ska inte ändra vem du är.

Gränssnittet mot lagringen är smalt med flit — `load_all` / `put` / `delete` / `clear` — så
`JsonDirStore` kan bytas mot en SQLite- eller Postgres-backad store utan att något annat rörs.
`--no-store` väljer `MemoryStore` och rör aldrig disken. Äldre `visits.json` flyttas över till
mappformatet automatiskt vid start, och originalet döps om till `visits.json.migrerad`.

Taket ligger på 100 besök; äldre rader raderas från både minnet och disken. Vill du rensa allt,
ta bort mappen `visits/` — sidan har inga knappar för att radera, eftersom sparningen numera är
automatisk och en felklickad knapp hade kostat jämförelsen.

Att sparningen nu är automatisk betyder att en server som körs med `--host 0.0.0.0` skriver ner
varje besökare som surfar in. Kör med `--no-store` om det inte är vad du vill.

**5 — Vad som vet att du är du.** En matris över alla sparade besök: attribut som rader,
besök som kolumner, värdegrupp som bokstav och färg i varje cell. Rader som är enfärgade är
identiska i varje besök — det är den mängden som beskriver maskinen och nätet snarare än
webbläsaren, och den bryr sig inte om att du bytt program eller gått till privat läge.

**6 — Profilen de bygger.** En knapp som sätter ihop de insamlade värdena till påståenden på
vanlig svenska: *"Kör Linux x86_64 med 8 kärnor"*, *"kring Stockholm"*, *"troligen utvecklare —
har Fira Code installerat"*. Varje påstående anger sin källa. Inget nytt mäts; poängen är vad
de redan tagna värdena betyder tillsammans.

**7 — Unik i rummet** (`--board`). Entropisiffrorna i sidan är uppskattningar. Det här är mätt:
hur många av dem som faktiskt surfat in på servern delar dina värden? Kör med
`--host 0.0.0.0 --board`, låt ett rum med folk gå in, och unikheten blir konkret i stället för
teoretisk. Ett attribut räknas bara som utpekande om minst två besökare rapporterat ett värde —
annars står "för få mätvärden", eftersom avsaknad av jämförelsematerial inte är ett bevis.

Läget samlar uppgifter om andra personer än den som startat servern, och är därför bakom en
flagga och avstängt som standard. Inget skrivs till disk.

## Så här hittar jag dig (avsnitt 6)

Svarar på frågan *"vad är det som gör att du ser mig och vet att jag är samma person?"* —
genom att räkna ut det i stället för att påstå det.

Girig sökning över alla observerade webbläsare: välj upprepat det attribut som skär bort flest
av de kvarvarande kandidaterna, tills bara en är kvar. Resultatet är en **minimal mängd** som
räcker för att peka ut just den webbläsaren, visad som en tratt där antalet krymper steg för
steg. Sedan körs sökningen om en gång per valt attribut, med det attributet borttaget, för att
svara på den avgörande frågan: **finns det en annan väg fram?** Nästan alltid finns det det,
och det är därför enskilda knep sällan räcker.

Sist korsas den utpekande mängden med de attribut som var konstanta genom alla dina besök
(avsnitt 5). Det är den delmängden som binder ihop besöken till en och samma person.

### Klartextrutan

Uträkningen är teknisk, så avsnittet inleds med en ruta som säger samma sak som en människa,
med de faktiska värdena i stället för hashar och attributnamn:

> **Jag känner igen dig på tre saker:**
> 1. att ditt grafikkort är **NVIDIA GeForce RTX 4070**
> 2. att din klocka står på **Stockholm**
> 3. att du har **Fira Code** installerat, vilket de flesta inte har
>
> Det räcker. Av de **23 webbläsare** den här servern sett är du den enda med just den
> kombinationen — och jag behövde aldrig fråga dig om något av det. Du bara besökte sidan.
>
> Och nej, det hjälper inte att dölja just de sakerna. Jag provade: tar jag bort vilken som
> helst av dem hittar jag dig på nästa i stället.

Hashar visas aldrig i klartext — «ett avtryck av hur just din dator ritar text» säger mer än
32 tecken hex. Grafikkortsnamn plockas ur Chromes `ANGLE (tillverkare, modell, bakända)`-format,
och programvarurendering beskrivs som vad den är i stället för med ett modellnamn.

Räknat mot de webbläsare servern faktiskt observerat, inte mot världen — vilket står i rutan.

## Nivån: hur lätt är du att följa?

Överst på sidan, före allt annat. Medvetet **två axlar och ingen enda poäng** — ett "72/100"
hade motsagt allt annat på sajten.

- **Exponering** — hur stor andel av den uppskattade entropin som faktiskt går att läsa.
- **Länkbarhet** — hur väl det som läses följer dig mellan besök.

Distinktionen är hela poängen: en webbläsare som läcker allt men slumpar värdena varje gång är
svårare att följa än en som läcker hälften och är stabil.

Två skilda mekanismer sänker länkbarheten, och båda mäts i stället för att gissas:

- **Randomisering** — samma avläsning körs två gånger i samma sidladdning och jämförs. Skiljer
  de sig slumpar webbläsaren aktivt. Servern kompletterar med hur många skilda fingeravtryck
  den sett från samma webbläsare över tid.
- **Harmonisering** — UTC som tidszon, kapad typsnittslista, få rapporterade kärnor, dolt WebGL,
  avsaknad av Client Hints. Värdena går att läsa men delas med alla andra användare av samma
  webbläsare.

Den andra halvan var först inte med, och då bedömdes **Tor Browser som "Lätt att följa"** —
vilket är rakt fel, eftersom Tor inte randomiserar utan harmoniserar. Utfallet nu, mot
syntetiska profiler:

| Profil | Nivå | Exponering | Länkbarhet |
| --- | --- | --- | --- |
| Vanlig Chrome | Genomskinlig | 100 % | 100 % |
| Vanlig Firefox | Lätt att följa | 93 % | 84 % |
| Mullvad Browser | Vanlig | 77 % | 52 % |
| Brave | Svår att följa | 100 % | 15 % |
| Tor Browser | Svår att följa | 77 % | 22 % |

Brave och Tor hamnar högst av motsatta skäl — Brave för att värdena ändrar sig, Tor för att de
delas med alla andra. Nivån listar dessutom varje fynd åt båda håll, så att siffran går att
granska i stället för att tas på tro.

**Vad nivån inte vet**, och säger så rakt ut på sidan: den mäter bara teknisk
fingeravtryckbarhet. Den vet ingenting om huruvida du är inloggad, och är du inloggad spelar
ingen av siffrorna någon roll. Den ser heller inte hur *ovanligt* ditt värde är i världen, bara
om det går att läsa — för uppmätt unikhet krävs klassrumsläget.

## Skyddsguiden (`/skydd`)

Den konstruktiva utgången ur resten av sajten, och den enda sidan som säger vad man ska göra.
Den är byggd kring två idéer som skiljer den från vanliga tio-tips-listor:

- **Hotbilden först.** Samma åtgärd är avgörande mot en motpart och ren teater mot en annan.
  En skriptfri väljare (radioknappar och CSS) byter mellan annonsnätverk, nätägaren, någon nära
  dig och arbetsgivaren — med vad som biter och vad som är teater för var och en.
- **Varje åtgärd med sitt pris.** Alla kort anger vad åtgärden gör, vad den *inte* skyddar mot
  och vad den kostar. Grön kant = värd det för de flesta, gul = beror på, röd = falsk trygghet.

Råden pekar tillbaka till belägget i verktyget, så att läsaren kan se varje påstående på sin
egen maskin i stället för att ta guiden på orden.

Sidan innehåller ett eget avsnitt med invändningarna på allvar — annonsblockering som dränerar
finansieringen för sajter man vill ska finnas, anonymitetsverktyg som skyddar även dem man inte
vill skydda, och avvägningen mellan integritet och arbetsgivarens behov av att upptäcka intrång.
En sida som bara argumenterar för integritet är propaganda, inte utbildning.

Som `/noscript` kör den noll skript.

## Fingeravtryck utan JavaScript (`/noscript`)

Resten av sidan kräver att skript får köra. Det här avsnittet gör inte det, och finns därför
alltid tillgängligt — ingen flagga behövs.

Sidan innehåller noll `<script>`-taggar. Allt den gör är att hämta en stilmall, och stilmallen
är skriven så att den röjer dig:

- **Mediafrågor** som slår till laddar var sin bakgrundsbild. Servern ser vilka förfrågningar
  som kom in och vet därmed skärmbredd, höjd, pixeltäthet, färgläge, färgomfång, pekdon,
  hovring, kontrast- och rörelseval, visningsläge — och, via `@media (scripting: none)`,
  om JavaScript över huvud taget var påslaget.
- **`@font-face` med `local()`** avslöjar installerade typsnitt. Finns typsnittet används det och
  ingen adress hämtas; saknas det hämtas reservadressen. En *utebliven* förfrågan är alltså
  också information — och det är så servern vet vilka typsnitt du har.

Typsnitten ger operativsystem (Calibri och Cambria → Windows, Menlo → macOS, DejaVu och
Liberation → Linux), yrkesgissning (JetBrains Mono, Fira Code) och språkpaket.

Resultatsidan uppdaterar sig själv med `<meta http-equiv="refresh">` — också utan skript.

Verifierat i Firefox med `javascript.enabled=false`: 30 förfrågningar till servern, 13 signaler,
och sonden rapporterade själv att JavaScript var avstängt. Samma sak i Chromium. Att blockera
skript hjälper alltså inte mot något av det här.

## Tredjepartsdemon (`--demo`)

Svarar på frågan *"hur spårar Google och Meta mig utan att jag godkänt något?"*

Servern startar tre lyssnare på loopback. Skilda värdnamn ger skilda origins och skilda
cookie-burkar, så det är en äkta tredjepartssituation och inte en simulering:

| Värd | Roll |
| --- | --- |
| `127.0.0.1` | Sajt A — nyhetssidan |
| `127.0.0.2` | Sajt B — webbutiken |
| `127.0.0.3` | Spårningsnätverket |

Båda sajterna bäddar in en 1×1-pixel och ett skript från nätverket, precis som Meta Pixel och
Google Analytics. Gå till `/demo`, besök båda sajterna, öppna sedan nätverkets egen vy på
`http://127.0.0.3:PORT/t/`. Där ligger din profil: vilka sajter du setts på, din IP, din
User-Agent och spåret med tidsstämplar — från en värd du aldrig öppnat.

Två detaljer som är själva lärdomen:

- **Tredjepartscookien blockeras** av moderna webbläsare som standard. Nätverket delar ut ett
  nytt id vid varje träff och kan inte följa dig den vägen. **Fingeravtrycket binder ändå ihop
  besöken.** Du gör rätt och blir spårad i alla fall.
- **Referer kortas** av webbläsaren till bara ursprunget vid anrop över origin-gränsen — ett
  verkligt skydd. Men spårningstaggen skickar hela adressen som en egen frågeparameter.
  Vyn visar båda kolumnerna bredvid varandra, så man ser skyddet och kringgåendet samtidigt.

Verifierat i webbläsare: cookien fungerar förstaparts men returneras aldrig som tredjepart,
medan fingeravtrycket kopplar ihop båda sajterna.

## Avgränsningar

- **Entropisiffrorna är indikativa.** De är additiva per attribut och bortser från att
  attributen korrelerar (en Mac med Retina-skärm och Safari är inte tre oberoende fakta).
  För mätningar mot en verklig population finns EFF:s Cover Your Tracks och AmIUnique.
- **Mot loopback blir IP-raden 127.0.0.1.** Kör med `--host 0.0.0.0` och surfa in från en
  annan enhet om du vill se en riktig adress i fältet.
- **Allt stannar lokalt.** Ingen extern förfrågan. Det enda som skrivs till disk är
  certifikatet och de sparade besöken (mappen `visits/`, avstängbart med `--no-store`).
  Övrigt minne töms när processen avslutas.

## Filer

| Fil | Innehåll |
| --- | --- |
| `server.py` | HTTP(S)-server, ClientHello-parser och JA3-beräkning, API:er |
| `static/index.html` | Sidans struktur och avsnittet om motåtgärder |
| `static/app.js` | Klientsidans collectors, en per rad med entropi och motåtgärd |
| `static/style.css` | Utseende |

### Lägga till en egen avläsning

Lägg till ett objekt i `COLLECTORS` i [static/app.js](static/app.js):

```js
{
  group: 'Enhet & status', id: 'mitt-test', label: 'Vad det heter', bits: 4, stable: true,
  fix: 'Vad som faktiskt hjälper mot just det här.',
  run: async () => { /* returnera en sträng */ },
}
```

`stable: true` betyder att värdet räknas in i det sammansatta fingeravtrycket — sätt det bara
för värden som inte ändras mellan omladdningar, annars bryts igenkänningen i avsnitt 3.
