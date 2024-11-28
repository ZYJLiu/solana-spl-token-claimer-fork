#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: ./run_migration <migration_name>"
  exit 1
fi

echo "Argument: $1"
cp "Anchor.toml" "Anchor.toml.bak";
echo -e "\n$1 = \"yarn run ts-mocha -p ./tsconfig.json -t 1000000 migrations/$1.ts\"" >> "Anchor.toml"
anchor run $1;
mv "Anchor.toml.bak" "Anchor.toml";
