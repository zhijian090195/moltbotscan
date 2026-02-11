import { ContentScanner } from '../sdk/scanner.js';
import { ScanResult, MiddlewareOptions } from '../types/index.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      scanResult?: ScanResult;
    }
  }
}

export function createMiddleware(options?: MiddlewareOptions) {
  const scanner = new ContentScanner({
    useLLM: options?.useLLM,
    apiKey: options?.apiKey,
  });

  const contentField = options?.contentField ?? 'message';

  return async function moltbookScan(
    req: { body?: Record<string, unknown>; scanResult?: ScanResult },
    res: { status: (code: number) => { json: (body: unknown) => void } },
    next: (err?: unknown) => void
  ): Promise<void> {
    try {
      const body = req.body;
      if (!body) {
        next();
        return;
      }

      const content =
        typeof body[contentField] === 'string'
          ? (body[contentField] as string)
          : typeof body === 'string'
            ? body
            : JSON.stringify(body);

      const result = await scanner.scan(content);
      req.scanResult = result;

      const shouldBlock =
        (options?.blockHighRisk && result.risk === 'HIGH') ||
        (options?.blockMediumRisk &&
          (result.risk === 'HIGH' || result.risk === 'MEDIUM'));

      if (shouldBlock) {
        if (options?.onBlock) {
          options.onBlock(result);
        }
        res.status(403).json({
          error: 'Content blocked by security scan',
          risk: result.risk,
          flags: result.flags,
        });
        return;
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}
