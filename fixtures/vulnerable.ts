// Deliberately vulnerable TypeScript file used to exercise the analyzer.

const dbPassword = "hunter2";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

// TODO: sanitize input before release
const input = process.argv[2];
const payload = input;
eval(payload);

const dynamic = new Function("return 1");

export function greet(name: string): string {
  return `hello ${name}`;
}
