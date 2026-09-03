// Ambient shim so the fixture compiles without @types/node (keeps the test
// suite offline). Not part of the code under analysis.
declare module "node:child_process" {
  export function execFile(
    file: string,
    args: string[],
    cb: (err: unknown, stdout: string, stderr: string) => void
  ): void;
}
