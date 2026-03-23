import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { createApiLoggerMiddleware } from 'api-logger-mongodb';
import { WafModule, WafPolicyGuard } from 'node-waf-middleware';
import { AppController } from './app.controller';

@Module({
  imports: [
    WafModule.forRoot({
      mode: 'block',
      policyVersion: 'nest-example-1.0.0',
      rulesetVersion: '2026.03-example',
      queryDecode: { enabled: true, htmlEntities: true },
      sqlInjection: { enabled: true },
      xss: { enabled: true, allowlistedBodyKeys: ['content'] },
    }),
  ],
  controllers: [AppController],
  providers: [{ provide: APP_GUARD, useClass: WafPolicyGuard }],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(
        createApiLoggerMiddleware({
          mongoUri: process.env.MONGO_URI || 'mongodb://127.0.0.1:27017',
          databaseName: 'waf_examples',
          collectionName: 'api_audit_nest',
          logRequestBody: true,
          logResponseBody: true,
          maskFields: ['password', 'token', 'authorization'],
          getUserInfo: (req: any) => ({
            id: req.user?.id || 'anonymous',
            email: req.user?.email,
            role: req.user?.role || 'guest',
            tenant: req.user?.tenant || 'public',
          }),
          transformLog: (entry: any) => {
            const traceId = entry?.request?.headers?.['x-request-id'] || `trace-${Date.now()}`;
            return {
              ...entry,
              traceId,
              security: {
                waf: {
                  package: 'node-waf-middleware',
                  policyVersion: 'nest-example-1.0.0',
                  rulesetVersion: '2026.03-example',
                },
                logger: {
                  package: 'api-logger-mongodb',
                  collection: 'api_audit_nest',
                },
              },
            };
          },
        })
      )
      .forRoutes('*');
  }
}
