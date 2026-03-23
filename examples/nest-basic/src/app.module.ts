import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { WafModule, WafPolicyGuard } from 'node-waf-middleware';
import { AppController } from './app.controller';

@Module({
  imports: [
    WafModule.forRoot({
      mode: 'block',
      sqlInjection: { enabled: true },
    }),
  ],
  controllers: [AppController],
  providers: [{ provide: APP_GUARD, useClass: WafPolicyGuard }],
})
export class AppModule {}
