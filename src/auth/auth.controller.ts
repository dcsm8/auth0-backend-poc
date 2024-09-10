import {
  Controller,
  Post,
  Body,
  UnauthorizedException,
  Headers,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { JwksClient } from 'jwks-rsa';
import * as jwt from 'jsonwebtoken';

@Controller('auth')
export class AuthController {
  private jwksClient: JwksClient;

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {
    this.jwksClient = new JwksClient({
      jwksUri: `https://${this.configService.get<string>('AUTH0_DOMAIN')}/.well-known/jwks.json`,
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
    });
  }

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

  @Post('exchange-auth0-token')
  async exchangeAuth0Token(@Headers('authorization') authHeader: string) {
    if (!authHeader) {
      throw new UnauthorizedException('No token provided');
    }

    const token = authHeader.split(' ')[1];

    try {
      const decodedToken = await this.verifyAuth0Token(token);

      // Create a new token with your application's format
      const payload = {
        sub: decodedToken.sub,
        email: decodedToken.email,
        name: decodedToken.name,
        // Add any other claims you want to include
      };

      const accessToken = this.jwtService.sign(payload);
      return { accessToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid Auth0 token');
    }
  }

  private async verifyAuth0Token(token: string): Promise<any> {
    const decodedToken = jwt.decode(token, { complete: true });
    if (!decodedToken || typeof decodedToken === 'string') {
      throw new Error('Invalid token');
    }

    const kid = decodedToken.header.kid;
    const key = await this.jwksClient.getSigningKey(kid);
    const signingKey = key.getPublicKey();

    return new Promise((resolve, reject) => {
      jwt.verify(
        token,
        signingKey,
        {
          audience: this.configService.get<string>('AUTH0_AUDIENCE'),
          issuer: `https://${this.configService.get<string>('AUTH0_DOMAIN')}/`,
          algorithms: ['RS256'],
        },
        (err, decoded) => {
          if (err) {
            reject(err);
          } else {
            resolve(decoded);
          }
        },
      );
    });
  }
}
