import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getProfile(user: any) {
    return {
      message: 'Profile information',
      user,
    };
  }
}
