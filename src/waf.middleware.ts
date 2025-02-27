import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class WafMiddleware implements NestMiddleware {
    use(req: Request, res: Response, next: NextFunction) {
        const { query, body } = req;

        const validSortValues = ['ASC', 'DESC'];

        // Normalize query parameter keys to lowercase for consistent validation
        const standardizedQuery = Object.keys(query).reduce((acc, key) => {
            acc[key.toLowerCase()] = query[key];
            return acc;
        }, {} as Record<string, any>);

        // Remove empty query parameters
        Object.keys(standardizedQuery).forEach(key => {
            if (standardizedQuery[key] === '') {
                delete standardizedQuery[key];
            }
        });

        // Validate sorting-related parameters and sanitize field names
        for (const key of Object.keys(standardizedQuery)) {
            const value = standardizedQuery[key];

            if (key.includes('sort')) {
                const valueStr = Array.isArray(value) ? value[0] : value;
                if (typeof valueStr === 'string' && !validSortValues.includes(valueStr.toUpperCase())) {
                    return res.status(403).json({ message: 'Invalid input detected. Request blocked.' });
                }
            }

            if (key.includes('order') || key.includes('field')) {
                if (!/^[a-zA-Z0-9_]+$/.test(value)) {
                    return res.status(400).json({ message: 'Invalid input detected. Request blocked.' });
                }
            }
        }

        const isSqlInjected = (input: any, isFreeText = false, isPassword = false, isEmail = false): boolean => {
            if (!input) return false;
            const inputStr = typeof input === 'object' ? JSON.stringify(input) : String(input).trim();

            if (isPassword) {
                return /(\bSELECT\b|\bDROP\b|\bTABLE\b|\bUNION\b|\bWHERE\b|\bOR\b|\bAND\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)/gi.test(inputStr);
            }

            if (isEmail) {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                return !emailRegex.test(inputStr);
            }

            const sqlPatterns = [
                /\b(OR|AND)\b\s*\d*\s*=\s*\d*/gi,
                /\b(UNION\s+SELECT|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|UPDATE\s+SET)\b/gi,
                /(--|#|\/\*)/g,
                /\b(EXEC|EXECUTE|SLEEP|WAITFOR|DELAY|HAVING|CAST|CONVERT)\b\s*\(/gi,
                /['"][\s]*OR[\s]+['"]?[\d]+=[\d]+/gi,
                /['"][\s]*AND[\s]+['"]?[\d]+=[\d]+/gi,
                /(\x53\x45\x4C\x45\x43\x54|\x44\x52\x4F\x50|\x54\x41\x42\x4C\x45)/gi,
            ];

            if (!isFreeText) {
                return sqlPatterns.some(pattern => pattern.test(inputStr));
            }

            return sqlPatterns.some(pattern => pattern.test(inputStr)) &&
                /(\bTABLE\b|\bFROM\b|\bWHERE\b|\bINTO\b|\bVALUES\b|\bSET\b)/gi.test(inputStr);
        };

        // Validate query parameters
        for (const key of Object.keys(standardizedQuery)) {
            if (isSqlInjected(standardizedQuery[key])) {
                return res.status(400).json({ message: 'Invalid input detected. Request blocked.' });
            }
        }

        // Validate body parameters
        if (body && typeof body === 'object') {
            for (const key of Object.keys(body)) {
                const value = body[key];

                const isEmailField = key.toLowerCase().includes('email');
                const isPasswordField = key.toLowerCase().includes('password');

                if ((isEmailField && isSqlInjected(value, false, false, true)) ||
                    (isPasswordField && isSqlInjected(value, false, true)) ||
                    (typeof value === 'number' || typeof value === 'boolean') && isSqlInjected(value) ||
                    (typeof value === 'string' && !/\s/.test(value) && isSqlInjected(value)) ||
                    (typeof value === 'string' && /\s/.test(value) && isSqlInjected(value, true))) {
                    return res.status(403).json({ message: 'Invalid input detected. Request blocked.' });
                }
            }
        }

        // XSS Protection
        const xssPattern = /(<script.*?>.*?<\/script>|javascript:|on\w+\s*=)/gi;
        if (xssPattern.test(JSON.stringify(standardizedQuery)) || xssPattern.test(JSON.stringify(body))) {
            return res.status(403).json({ message: 'Potential XSS attack detected' });
        }

        next();
    }
}
