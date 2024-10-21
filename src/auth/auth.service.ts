import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async verifyToken(token: string) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid token',
      });
    }
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });
      if (user)
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'User already exists',
        });

      const newUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name,
        },
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: pwd, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: error.error.status,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });
      if (!user)
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Invalid credentials',
        });

      const isValidPassword = bcrypt.compareSync(password, user.password);

      if (!isValidPassword)
        throw new RpcException({
          status: HttpStatus.UNAUTHORIZED,
          message: 'Invalid credentials',
        });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: pwd, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: error.error.status,
        message: error.message,
      });
    }
  }
}
