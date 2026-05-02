/**
 * @file base.ts
 * Base class for API client modules
 */

/**
 * Base class for API client methods
 */
export abstract class BaseApiClient {
  protected abstract makeRequest<T>(
    method: string,
    path: string,
    data?: Record<string, unknown> | string | number | boolean,
    headers?: Record<string, string>
  ): Promise<T>;
}
