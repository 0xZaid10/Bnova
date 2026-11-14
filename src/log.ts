// Structured JSON logs. Never pass secrets or full signatures to these functions.
const order = { debug: 0, info: 1, warn: 2, error: 3 } as const;
type Level = keyof typeof order;
let current: Level = "info";

export function setLogLevel(l: Level) {
  current = l;
}

function emit(level: Level, msg: string, extra?: Record<string, unknown>) {
  if (order[level] < order[current]) return;
  const line = JSON.stringify({ t: new Date().toISOString(), level, msg, ...extra });
  (level === "error" ? process.stderr : process.stdout).write(line + "\n");
}

export const log = {
  debug: (m: string, e?: Record<string, unknown>) => emit("debug", m, e),
  info: (m: string, e?: Record<string, unknown>) => emit("info", m, e),
  warn: (m: string, e?: Record<string, unknown>) => emit("warn", m, e),
  error: (m: string, e?: Record<string, unknown>) => emit("error", m, e),
};
