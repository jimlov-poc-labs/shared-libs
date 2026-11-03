# shared-libs

Gemensamt funktionsbibliotek för jimlov-poc-labs. Här bor **mekanismer** som flera
projekt behöver (parsning, validering, signering, spärrar) i Python och TypeScript
med samma beteende. Privat repo, ingen privat registry.

**Dela mekanismen, aldrig policyn.** Inga affärsregler, prompter, mallinnehåll eller
allowlists hör hemma här. Bibliotek tar sådant som indata; konsumenten äger det.

## Struktur

| Mapp | Innehåll |
|---|---|
| `spec/<förmåga>/` | Språkoberoende beskrivning (`README.md`) och testvektorer (`vektorer.json`) |
| `py/<förmåga>/` | Python-paket (`pyproject.toml`, `src/`, `tests/`) |
| `ts/<förmåga>/` | TypeScript-paket (`package.json`, `src/`, `tests/`) |

Mappnamnet är detsamma i `spec/`, `py/` och `ts/`; CI använder det för att veta vilka
paket en ändring berör. Mappar som börjar på `_` är exempel och ingen riktig förmåga.
`_exempel` visar mönstret: båda språken läser `spec/_exempel/vektorer.json`, så samma
testfall bevisar samma beteende.

## Lägga till en förmåga

1. Skriv `spec/<förmåga>/README.md` (kontrakt, felfall) och `vektorer.json` först.
2. Kopiera `py/_exempel` och/eller `ts/_exempel` till `py/<förmåga>` / `ts/<förmåga>`; byt namn i `pyproject.toml` / `package.json`, sätt version `0.1.0`, ta bort `"private": true` om den ska konsumeras. Behåll `"files": ["dist"]` så tarballen bara innehåller byggd kod.
3. Låt testerna läsa vektorerna i `spec/`. Nya fall läggs i vektorfilen, inte bara i ett språk.
4. Lägg katalogen i `.github/dependabot.yml`. Sonar och CI plockar upp paketet själva.
5. Checka in `package-lock.json` (TypeScript); CI kör `npm ci`.
6. Tagga när PR är mergad (se nedan).

## Konsumera (pinna på tagg)

Taggar: `<förmåga>-py/vX.Y.Z` och `<förmåga>-ts/vX.Y.Z`. Pinna alltid på tagg, aldrig gren.

Python:

    pip install "shared-libs-proof @ git+https://github.com/jimlov-poc-labs/shared-libs.git@proof-py/v1.2.0#subdirectory=py/proof"

(`requirements.txt` accepterar samma rad.) CI och deploy behöver läsrätt mot repot,
t.ex. deploy key eller token.

TypeScript: npm kan inte installera från en underkatalog i ett git-beroende, så
TS-förmågor distribueras som färdigpaketerad `.tgz` bifogad på en GitHub Release
(`release.yml` bygger den när taggen `<förmåga>-ts/vX.Y.Z` pushas). Konsumentens rad:

    npm i https://github.com/jimlov-poc-labs/shared-libs/releases/download/<förmåga>-ts/vX.Y.Z/<paket>-X.Y.Z.tgz

`<paket>` är paketnamnet utan `@` och med `/` ersatt av `-` (`@shared-libs/exempel`
blir `shared-libs-exempel-0.0.0.tgz`). Releasen avvisas om taggens version inte
matchar `package.json`. Python-taggar (`<förmåga>-py/vX.Y.Z`) ger bara en release med
auto-genererade noter, ingen artefakt; Python pinnas på git-taggen enligt ovan.

Privat repo (**ej provat**): nedladdning av release-tillgångar kräver autentisering,
så en anonym `npm i <url>` ger 404. I CI behövs en token med läsrätt (`contents: read`
på detta repo, t.ex. fine-grained PAT eller GitHub App-token) som skickas som
`Authorization`-header; hur npm bäst får med headern (t.ex. förhämtning med
`gh release download` och `npm i ./fil.tgz`) är inte validerat.

Dependabot: uppdaterar inte URL-beroenden till tarballs och ser inte nya releaser.
Nya versioner i konsumentrepona måste höjas manuellt (eller via eget skript);
tillgängliga uppdateringar syns alltså inte automatiskt. Python-git-pinnar har samma
begränsning i praktiken.

## Versionspolicy

Semver per paket. Brytande ändring = ny major. Ny funktion = minor. Fix = patch.
**En säkerhetsfix får skärpa beteende** (neka något som tidigare släpptes igenom)
även i patch/minor; det räknas inte som brytande. Release noteras med vad som skärpts.
Taggen sätts på mergad main och är oföränderlig.

## Definition of done för kod

- Saknad, tom, trasig eller utgången indata stänger, aldrig öppnar (fail closed).
- Samma spärr på varje väg som når ett skyddat tillstånd, inte bara huvudvägen.
- Ägarskap kontrolleras (rätt objekt, rätt ägare), inte bara anroparens identitet.
- Dyra operationer har rate limit.
- Beroenden aktuella och utan kända sårbarheter (CI: pip-audit, npm audit, Dependabot).
- Skyddet passar sammanhanget (URL-schemakontroll i stället för HTML-escape för länkar; parametriserade frågor).
- Tester som faller utan fixen: ett test per buggfix/spärr som bevisat är rött utan ändringen.
- Beteende som delas mellan språk bevisas av samma testvektor i `spec/`.

## CI

| Workflow | Gör |
|---|---|
| `ci.yml` | Hittar berörda paket (`.github/scripts/andrade-paket.sh`) och kör per paket: Py 3.12 ruff, mypy strict, pytest, pip-audit; TS Node 20 och 22 eslint, tsc, vitest, npm audit. Ändring i `.github/` eller `sonar-project.properties`, eller saknad jämförelsepunkt, testar alla paket. |
| `sakerhet.yml` | gitleaks (Portis-mönstret) |
| `sonar.yml` | Täckning + SonarQube mot `sonar.jimlov.se` |
| `kontraktstest.yml` | Skiss, se nedan |

npm audit: körtidsberoenden stoppar på alla nivåer, utvecklingsberoenden från high.
(Vid skelettet finns en känd moderate i eslints minimatch utan fix; dev-only.)

## Kontraktstest (skiss, ej aktiv)

`kontraktstest.yml` startas manuellt (`workflow_dispatch`) och kör en konsuments egna
tester med en kandidatversion av en förmåga installerad från en gren/tagg här. Tanken
är att upptäcka brott innan en ny major/minor taggas. Kräver secret `KONTRAKT_TOKEN`
(läsrätt mot konsumentrepot) och är begränsat till repon i `jimlov-poc-labs`. Ingen
konsument är kopplad och flödet är inte körprovat.

## Måste skapas manuellt

- Sonar-projektet `shared-libs` på sonar.jimlov.se.
- Repo-secret `SONAR_TOKEN` (utan den failar `sonar.yml`).
- Senare, för kontraktstest: secret `KONTRAKT_TOKEN`.

## Lokalt

    # Python
    cd py/_exempel && python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
    .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest

    # TypeScript
    cd ts/_exempel && npm ci && npm run lint && npm run typecheck && npm test
