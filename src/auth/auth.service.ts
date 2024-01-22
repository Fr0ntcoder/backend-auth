import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { verify } from 'argon2'
import { Response } from 'express'
import { AuthDto } from 'src/auth/dto/auth.dto'
import { UserService } from 'src/auth/user.service'

@Injectable()
export class AuthService {
  EXPIRE_DAY_REFRESH_TOKEN = 1
  REFRESH_TOKEN_NAME = 'refreshToken'

  constructor(
    private jwt: JwtService,
    private userService: UserService,
  ) {}

  async login(dto: AuthDto) {
    const { password, ...user } = await this.validateUser(dto)
    const tokens = await this.issueTokens(user.id)

    return { user, ...tokens }
  }

  async register(dto: AuthDto) {
    /*  const oldUser = await this.usersService.getByEmail(dto.email)

    if (oldUser) {
      throw new BadRequestException('Пользователь уже существует')
    }

    const { ...user } = await this.usersService.create(dto)

    const tokens = await this.issueTokens(user.id)

    return {
      user,
      ...tokens,
    } */

    const oldUser = await this.userService.getByEmail(dto.email)

    if (oldUser) throw new BadRequestException('User already exists')

    const { password, ...user } = await this.userService.create(dto)

    const tokens = await this.issueTokens(user.id)

    return {
      user,
      ...tokens,
    }
  }

  async getNewTokens(refreshToken: string) {
    const result = await this.jwt.verifyAsync(refreshToken)

    if (!result) {
      throw new UnauthorizedException('Не валидный refresh token')
    }

    const { password, ...user } = await this.userService.getById(result.id)

    const tokens = await this.issueTokens(user.id)

    return {
      user,
      ...tokens,
    }
  }

  private async issueTokens(userId: number) {
    const data = { id: userId }

    const accessToken = this.jwt.sign(data, { expiresIn: '1h' })

    const refreshToken = this.jwt.sign(data, {
      expiresIn: '7d',
    })

    return { accessToken, refreshToken }
  }

  private async validateUser(dto: AuthDto) {
    const user = await this.userService.getByEmail(dto.email)

    if (!user) {
      throw new NotFoundException('Польхователь не найден')
    }

    const isValid = await verify(user.password, dto.password)

    if (!isValid) {
      throw new UnauthorizedException('Не валидный пароль')
    }

    return user
  }

  addRefreshTokenToResponse(res: Response, refreshToken: string) {
    const expiresIn = new Date()
    expiresIn.setDate(expiresIn.getDate() + this.EXPIRE_DAY_REFRESH_TOKEN)

    res.cookie(this.REFRESH_TOKEN_NAME, refreshToken, {
      httpOnly: true,
      domain: 'localhost',
      expires: expiresIn,
      secure: true,
      sameSite: 'none', // lax prod
    })
  }

  removeRefreshTokenFromResponse(res: Response) {
    res.cookie(this.REFRESH_TOKEN_NAME, '', {
      httpOnly: true,
      domain: 'localhost',
      expires: new Date(0),
      secure: true,
      sameSite: 'none', // lax prod
    })
  }
}
