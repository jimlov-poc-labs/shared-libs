# _exempel: strikt_port / striktPort

Tar en sträng, returnerar porten (1-65535) som heltal eller null/None. Bara ASCII-siffror,
ingen inledande nolla, inga tecken eller blanksteg. Allt annat ger null (fail closed).
Kontraktet är `vektorer.json`; båda språken kör alla fall.
