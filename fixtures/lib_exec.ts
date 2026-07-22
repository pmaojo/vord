// Helper module: the sink lives here, one file away from the user input.

import cp from "child_process";

export function run(cmd: string): void {
  cp.execSync(cmd);
}

export function launch(command: string): void {
  run(command);
}
