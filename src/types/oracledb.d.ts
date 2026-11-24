declare module 'oracledb' {
  export interface ConnectionAttributes {
    user?: string;
    password?: string;
    connectString?: string;
    connectionString?: string;
    privilege?: number;
    connectTimeout?: number;
    configDir?: string;
    walletLocation?: string;
    walletPassword?: string;
  }

  export interface PoolAttributes extends ConnectionAttributes {
    poolMin?: number;
    poolMax?: number;
    poolIncrement?: number;
    poolTimeout?: number;
  }

  export type BindParameters =
    | Record<string, unknown>
    | unknown[];

  export interface ExecuteOptions {
    outFormat?: number;
    maxRows?: number;
  }

  export interface Result<T = Record<string, unknown>> {
    rows?: T[];
    metaData?: Array<{ name: string }>;
  }

  export interface Connection {
    execute<T = Record<string, unknown>>(
      sql: string,
      bindParams?: BindParameters,
      options?: ExecuteOptions
    ): Promise<Result<T>>;
    close(): Promise<void>;
    callTimeout?: number;
  }

  export interface Pool {
    getConnection(): Promise<Connection>;
    close(drainTime?: number): Promise<void>;
  }

  export const OUT_FORMAT_OBJECT: number;
  export const thin: boolean;

  export function initOracleClient(options?: {
    libDir?: string;
    configDir?: string;
  }): void;

  export function getConnection(
    attrs: ConnectionAttributes
  ): Promise<Connection>;

  export function createPool(
    attrs: PoolAttributes
  ): Promise<Pool>;
}