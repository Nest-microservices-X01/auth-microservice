import { Controller } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';
import { AuthService } from './auth.service';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  registerUser() {
    return 'register user';
  }

  @MessagePattern('auth.login.user')
  loginUser() {
    return 'login user';
  }

  @MessagePattern('auth.verify.user')
  verifyToken() {
    return 'verify token';
  }
}
