#!/usr/bin/env bash
# Skriver matriserna py=[...] och ts=[...] till $GITHUB_OUTPUT.
# Ett paket är berört om py/<namn>/, ts/<namn>/ eller spec/<namn>/ ändrats.
# Ändras .github/ eller sonar-project.properties testas alla paket.
# Saknas jämförelsepunkt (ny gren, tvingad push) testas alla: fail closed.
set -euo pipefail

bas="${BAS_SHA:-}"
if [[ -z "$bas" || "$bas" =~ ^0+$ ]] || ! git cat-file -e "$bas^{commit}" 2>/dev/null; then
  alla=1
  andrade=""
else
  alla=0
  andrade="$(git diff --name-only "$bas" HEAD)"
  if grep -qE '^(\.github/|sonar-project\.properties$)' <<<"$andrade"; then alla=1; fi
fi

matris() {
  local sprak="$1" forsta=1 ut="[" namn
  for d in "$sprak"/*/; do
    [[ -d "$d" ]] || continue
    namn="$(basename "$d")"
    if [[ "$alla" == 1 ]] || grep -qE "^($sprak|spec)/$namn/" <<<"$andrade"; then
      [[ "$forsta" == 1 ]] || ut+=","
      ut+="\"$namn\""
      forsta=0
    fi
  done
  echo "$ut]"
}

{
  echo "py=$(matris py)"
  echo "ts=$(matris ts)"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
