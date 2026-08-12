#!/bin/sh
# Download Holodeck B2B 8.1.1, install example + AS4.jl fixture certs, install P-Modes.
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
AS4="$(cd "$ROOT/../.." && pwd)"
HB2B="$ROOT/hb2b"
VER=8.1.1
ZIP="holodeckb2b-distribution-${VER}.zip"
URL="https://github.com/holodeck-b2b/Holodeck-B2B/releases/download/v${VER}/${ZIP}"

export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk}"
export PATH="$JAVA_HOME/bin:/opt/homebrew/bin:$PATH"
command -v java >/dev/null || { echo "Need OpenJDK (brew install openjdk)." >&2; exit 1; }
command -v keytool >/dev/null || { echo "Need keytool from the JDK." >&2; exit 1; }

cd "$ROOT"
if [ ! -f "$ZIP" ]; then
  echo "Downloading $URL …"
  curl -L --fail -o "$ZIP" "$URL"
fi

if [ ! -d "$HB2B" ]; then
  echo "Unpacking …"
  unzip -q "$ZIP"
  mv "holodeckb2b-${VER}" hb2b
fi

cp -f "$HB2B/examples/certs/"*.jks "$HB2B/repository/certs/"

# AS4.jl fixture cert — used to verify signed pushes from Julia
import_cert() {
  ks=$1; pass=$2; alias=$3; file=$4
  keytool -list -keystore "$ks" -storepass "$pass" -alias "$alias" >/dev/null 2>&1 && return 0
  keytool -importcert -noprompt -keystore "$ks" -storepass "$pass" -alias "$alias" -file "$file"
}
import_cert "$HB2B/repository/certs/partnerkeys.jks" nosecrets as4jl "$AS4/test/fixtures/cert.pem"
import_cert "$HB2B/repository/certs/trustedcerts.jks" trusted as4jl "$AS4/test/fixtures/cert.pem"

# Receiver P-Mode for AS4.jl fixture identity
cp -f "$ROOT/as4jl-push-resp.xml" "$HB2B/repository/pmodes/as4jl-push-resp.xml"
cp -f "$HB2B/examples/pmodes/ex-pm-push-resp.xml" "$HB2B/repository/pmodes/"

echo "Holodeck installed at $HB2B"
echo "Start:  $ROOT/start.sh"
echo "Stop:   $ROOT/stop.sh"
echo "AS4 URL: http://127.0.0.1:8080/holodeckb2b/as4"
