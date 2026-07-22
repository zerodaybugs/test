import fs from "node:fs/promises";
import path from "node:path";

import { generateTypeScript } from "@evolution-sdk/evolution/blueprint/codegen";
import { createCodegenConfig } from "@evolution-sdk/evolution/blueprint/codegen-config";
import type { PlutusBlueprint } from "@evolution-sdk/evolution/blueprint/types";

const cliSourceDir = path.resolve(process.cwd(), "src");
const cardanoRoot = path.resolve(process.cwd(), "../../../");
const blueprintPath = path.join(cardanoRoot, "plutus.json");
const outputPath = path.join(cliSourceDir, "offchain.ts");

const blueprint = JSON.parse(
  await fs.readFile(blueprintPath, "utf8"),
) as PlutusBlueprint;

const source = generateTypeScript(
  blueprint,
  createCodegenConfig({
    imports: {
      data: [
        "/** biome-ignore-all assist/source/useSortedKeys: generated code */",
        "/** biome-ignore-all assist/source/organizeImports: generated code */",
        'import { Data } from "@evolution-sdk/evolution";',
      ].join("\n"),
      tschema: 'import { TSchema } from "@evolution-sdk/evolution";',
    },
    useSuspend: false,
  }),
);

await fs.writeFile(outputPath, source);
console.log(`OFFCHAIN_BINDING_GENERATED=${outputPath}`);
