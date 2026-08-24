#!/usr/bin/env bash
set -e

node --run docs

calculate_import_path() {
  local md_file="$1"
  local depth
  depth=$(echo "$md_file" | awk -F'/' '{print NF-1}')
  printf '../%.0s' $(seq 1 "$depth")
}

extract_typescript_blocks() {
  local md_file="$1"
  local base_name="${md_file%.*}"
  local import_path
  import_path="$(calculate_import_path "$md_file")index.ts"

  pandoc -i "$md_file" -t json |
    jq -a '.blocks[] | select(.t == "CodeBlock" and .c[0][1][0] == "ts") | .c[1]' |
    jq -s >"${base_name}.tmp"

  node <<-EOF
    const fs = require('node:fs');
    const codeBlocks = JSON.parse(fs.readFileSync('${base_name}.tmp', 'ascii'));

    codeBlocks.forEach((code, index) => {
      const hasImport = code.includes('import * as PASETO');
      const content = hasImport
        ? code.replace('paseto', '${import_path}')
        : \`import * as PASETO from '${import_path}'\n\n\${code}\`;

      fs.writeFileSync(\`${base_name}.\${index}.ts\`, content);
    });
EOF

  rm "${base_name}.tmp"
}

for file in docs/README.md docs/**/*.md; do
  extract_typescript_blocks "$file"
done

tsc -p tsconfig.docs.json && find docs -type f -name '*.ts' -delete
