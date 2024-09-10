import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { AppService } from './app.service';
import { JwtAuthGuard } from './auth/jwt-auth.guard';

@Controller('api')
export class AppController {
  constructor(private appService: AppService) {}

  @UseGuards(JwtAuthGuard)
  @Get('protected')
  getProfile(@Request() req) {
    return req.user;
  }

  @Get('health')
  healthCheck() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };
  }
}
