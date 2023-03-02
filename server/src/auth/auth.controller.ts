import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { signUpDto } from './dto/signup.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService ) {}


    @Post('/signup')
    signUp(@Body() signUpDto: signUpDto): Promise<{ token: string }> {
        return this.authService.signUp(signUpDto)
    }

    @Post('/login')
    login(@Body() loginDto: LoginDto): Promise<{ token: string }> { 
        return this.authService.login(loginDto);
    }
        
}
