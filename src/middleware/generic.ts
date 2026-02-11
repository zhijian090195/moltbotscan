import { ContentScanner } from '../sdk/scanner.js';
import { ScanResult, MiddlewareOptions } from '../types/index.js';

export interface HandlerResult {
  allowed: boolean;
  result: ScanResult;
}

export function createHandler(options?: MiddlewareOptions) {
  const scanner = new ContentScanner({
    useLLM: options?.useLLM,
    apiKey: options?.apiKey,
  });

  return async function handle(content: string): Promise<HandlerResult> {
    const result = await scanner.scan(content);

    const blocked =
      (options?.blockHighRisk && result.risk === 'HIGH') ||
      (options?.blockMediumRisk &&
        (result.risk === 'HIGH' || result.risk === 'MEDIUM'));

    if (blocked && options?.onBlock) {
      options.onBlock(result);
    }

    return { allowed: !blocked, result };
  };
}
