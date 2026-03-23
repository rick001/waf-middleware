import { Body, Controller, Get, Post } from '@nestjs/common';
import { WafPolicy } from '@rick001/http-waf-middleware';

@Controller()
export class AppController {
  @Get('health')
  health() {
    return { ok: true };
  }

  @Post('search')
  search(@Body() body: { query?: string }) {
    return { ok: true, query: body?.query ?? null };
  }

  // Example per-route override with guard-based policy merge.
  @Get('admin/import')
  @WafPolicy({ mode: 'monitor' })
  importPreview() {
    return { ok: true, mode: 'monitor-on-this-route' };
  }
}
