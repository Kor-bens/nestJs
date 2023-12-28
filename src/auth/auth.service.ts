import { Injectable, NotFoundException, ConflictException, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from "bcrypt"
import * as speakeasy from "speakeasy";
import { SignupDto } from './dto/signupDto';
import { SigninDto } from './dto/signinDto';
import { PrismaService } from 'src/prisma/prisma.service';
import { MailerService } from 'src/mailer/mailer.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ResetPasswordDemandDto } from './dto/resetPasswordDemandDto';
import { ResetPasswordConfirmationDto } from './dto/resetPasswordConfirmationDto';


@Injectable()
export class AuthService {

    constructor(private readonly prismaService : PrismaService,
                private readonly emailService  : MailerService,
                private readonly JwtService : JwtService,
                private readonly configService : ConfigService
        ) {}
   async signup(signupDto: SignupDto) {
    const {email, password, username} = signupDto;
    // ** Vérifier si l'utilisateur est déjà inscrit
    const user =  await this.prismaService.user.findUnique({where : { email } });
    if (user) throw new ConflictException("User already exist");
    // ** Hasher le mot de passe
    const hash = await bcrypt.hash(password, 10);
    // ** Enregistrer l'utilisateur dans la base de données
    await this.prismaService.user.create({
    data : {email, username, password : hash},
    });
    // ** Envoyer un email de confirmation
    await this.emailService.sendSignupConfirmation(email);
    // ** Retourner une réponse de succès
       return {data : 'User successfully created'};
    }

   async signin(signinDto: SigninDto) {
    const {email, password}  = signinDto 
        // ** Vérifier si l'utilisateur est déjà inscrit
       const user = await this.prismaService.user.findUnique({where : {email}})
       if(!user) throw new NotFoundException('User not found');
        // ** Comparer le mot de passe 
        const match = await bcrypt.compare(password, user.password)
        if(!match) throw new UnauthorizedException("Password does not match")
        // ** Retourner un token jwt
        const payload = {
            sub : user.userId,
            email : user.email
        }
        const token = this.JwtService.sign(payload, {
            expiresIn : "2h",
            secret : this.configService.get("SECRET_KEY"),
        });

        return {
            token, user : {
                username : user.username,
                email    : user.email,
            }
        }
    }
   async resetPasswordDemand(resetPasswordDemandDto: ResetPasswordDemandDto) {
    const {email} = resetPasswordDemandDto;
    const user = await this.prismaService.user.findUnique({where : {email}})
    if(!user) throw new NotFoundException('User not found'); 
    const code = speakeasy.totp({
        secret : this.configService.get("OTP_CODE"),
        digits : 5,
        step : 60 * 15,
        encoding : "base32"
     })
     const url = "http://localhost:3000/auth/reset-password-confirmation"
     await this.emailService.sendResetPassword(email, url, code)
     return {data : "Reset password mail has been send"}
    }
   async resetPasswordConfirmation(resetPasswordConfirmationDto: ResetPasswordConfirmationDto) {
    const {code, email, password} = resetPasswordConfirmationDto; 
    const user = await this.prismaService.user.findUnique({where : {email}})
    if(!user) throw new NotFoundException('User not found'); 
    const match = speakeasy.totp.verify({
        secret: this.configService.get('OTP_CODE'),
        token: code,
        digits: 5,
        step: 60 * 15,
        encoding: 'base32',
    });
    if(!match) throw new UnauthorizedException("Invalid/expired token");
    const hash = await bcrypt.hash(password, 10)
    await this.prismaService.user.update({where : {email}, data : {password : hash}})
    return {data : "Password updated"}
    }
}
