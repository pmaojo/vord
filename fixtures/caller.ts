// User input entering here must be traced across the module boundary into
// the execSync sink inside lib_exec.ts.

import { launch } from "./lib_exec";

const target = process.argv[2];
launch(target);
