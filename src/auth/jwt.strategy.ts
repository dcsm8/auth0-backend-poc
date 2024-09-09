import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { passportJwtSecret } from 'jwks-rsa';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      audience: configService.get<string>('AUTH0_AUDIENCE'),
      issuer: `https://${configService.get<string>('AUTH0_DOMAIN')}/`,
      algorithms: ['RS256'],
      secretOrKeyProvider: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `https://${configService.get<string>('AUTH0_DOMAIN')}/.well-known/jwks.json`,
      }),
    });

    this.logger.log(`JWT Strategy initialized with:
      Audience: ${this.configService.get<string>('AUTH0_AUDIENCE')}
      Issuer: https://${this.configService.get<string>('AUTH0_DOMAIN')}/
      JWKS URI: https://${this.configService.get<string>('AUTH0_DOMAIN')}/.well-known/jwks.json`);
  }

  async validate(payload: any) {
    this.logger.log(`Validating payload: ${JSON.stringify(payload)}`);

    // You can add custom validation logic here
    // For example, checking if the user exists in your database

    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }

    return {
      userId: payload.sub,
      email: payload.email,
    };
  }
}
