import { Controller, Get } from '@nestjs/common';
import { WafPolicy } from 'node-waf-middleware';

@Controller()
export class AppController {
  @Get('health')
  health() {
    return { ok: true };
  }

  /** Merged over global options when `WafPolicyGuard` is active (not with `WafMiddleware` alone). */
  @Get('admin/import')
  @WafPolicy({ mode: 'monitor' })
  importPreview() {
    return { note: 'WAF monitor mode on this route' };
  }
}
