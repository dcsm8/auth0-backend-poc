import { Controller, Post, Body, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Controller('auth')
export class AuthController {
  constructor(private jwtService: JwtService) {}

  @Post('login')
  async login(@Body() credentials: { email: string; password: string }) {
    if (
      credentials.email === 'test@test.com' &&
      credentials.password === '1234'
    ) {
      const payload = { sub: '1', email: credentials.email };
      return {
        id: '1',
        name: 'Test User',
        email: credentials.email,
        access_token: this.jwtService.sign(payload),
      };
    }
    throw new UnauthorizedException('Invalid credentials');
  }
}
