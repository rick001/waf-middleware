import { NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
export declare class WafMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: NextFunction): Response<any, Record<string, any>> | undefined;
}
