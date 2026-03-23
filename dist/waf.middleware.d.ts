import { NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { type WafOptions } from './config';
export declare class WafMiddleware implements NestMiddleware {
    private readonly globalOptions;
    private readonly policies;
    private readonly policyResolver;
    constructor(options?: WafOptions);
    use: (req: Request, res: Response, next: NextFunction) => void;
}
