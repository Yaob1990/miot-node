//use chalk for coloring?
// https://www.npmjs.com/package/chalk
// example: https://github.com/homebridge/homebridge/blob/master/src/logger.ts
// also need to pass whether homebridge debug is enabled or not

class Logger {
  private deepDebugLog: boolean;
  private log: any;
  private readonly name: string;
  constructor(log?: Function, name?: string) {
    this.log = log || console;
    this.name = name || '';
    this.deepDebugLog = true;
  }

  setDeepDebugLogEnabled(enabled: boolean) {
    this.deepDebugLog = enabled;
  }

  isDeepDebugLogEnabled() {
    return this.deepDebugLog;
  }

  info(message: string, ...args: any[]) {
    this.log.info((this.name ? `[${this.name}] ` : '') + message, ...args);
  }

  warn(message: string, ...args: any[]) {
    this.log.warn((this.name ? `[${this.name}] ` : '') + message, ...args);
  }

  error(message: string, ...args: any[]) {
    this.log.error((this.name ? `[${this.name}] ` : '') + message, ...args);
  }

  debug(message: string, ...args: any[]) {
    this.log.debug((this.name ? `[${this.name}] ` : '') + message, ...args);
  }

  table(...args: any[]) {
    console.table(...args);
  }

  // extended
  deepDebug(message: string, ...args: any[]) {
    if (this.isDeepDebugLogEnabled()) {
      this.debug(message, ...args);
    }
  }
}

export default Logger;
