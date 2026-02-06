import { spawn } from 'node:child_process';
import { CommandResult } from '../types/index.js';

export function runCommand(
  command: string,
  args: string[],
  timeoutMs = 12000,
  cwd?: string,
  env?: NodeJS.ProcessEnv
): Promise<CommandResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { cwd, env: env ?? process.env });
    let stdout = '';
    let stderr = '';
    let done = false;

    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        child.kill('SIGKILL');
        resolve({ stdout, stderr: `${stderr}\nCommand timed out`, exitCode: 124, timedOut: true });
      }
    }, timeoutMs);

    child.stdout.on('data', (d) => (stdout += d.toString()));
    child.stderr.on('data', (d) => (stderr += d.toString()));

    child.on('error', (err) => {
      clearTimeout(timer);
      if (!done) {
        done = true;
        resolve({ stdout, stderr: `${stderr}\n${err.message}`, exitCode: 1, timedOut: false });
      }
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      if (!done) {
        done = true;
        resolve({ stdout, stderr, exitCode: code ?? 0, timedOut: false });
      }
    });
  });
}
