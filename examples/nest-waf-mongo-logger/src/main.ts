import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Demo user context for getUserInfo enrichment.
  app.use((req: any, _res: any, next: () => void) => {
    req.user = {
      id: req.get('x-user-id') || 'anonymous',
      email: req.get('x-user-email') || undefined,
      role: req.get('x-user-role') || 'guest',
      tenant: req.get('x-tenant-id') || 'public',
    };
    next();
  });

  const port = Number(process.env.PORT || 3004);
  await app.listen(port);
  console.log(`Nest + WAF + Mongo logger on http://127.0.0.1:${port}`);
  console.log(`Mongo URI: ${process.env.MONGO_URI || 'mongodb://127.0.0.1:27017'}`);
}

bootstrap().catch((err) => {
  console.error(err);
  process.exit(1);
});
