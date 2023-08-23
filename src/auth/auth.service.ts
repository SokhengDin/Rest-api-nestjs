import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { AuthEntity } from './entity/auth.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {

    constructor(private prisma: PrismaService, private jwtService: JwtService) {}

    async login(email: string, password: string): Promise<AuthEntity>{

        // Fetch user
        const user = await this.prisma.user.findUnique({
            where: {email: email}
        });


        // If not user
        if (!user) {
            throw new NotFoundException(`No user found for email: ${email}`);
        }

        // Check password if it is correct
        // bcrypt hashing
        const isPasswordValid = await bcrypt.hash(password, user.password);

        // If not password
        if (!isPasswordValid) {
            throw new UnauthorizedException('Invalid password');
        }

        return {
            accessToken: this.jwtService.sign({ userId: user.id })
        };
    }

}
