import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from '@namdp/auth';
import { join } from 'path';

@Module({
  imports: [
    AuthModule.forRoot({
      cls: {
        configFilePath: join(process.cwd(), 'cls.json'),
      },
      env: {
        prefix: '',
      },
      routes: {
        redirect: {
          successAuthenticatedWithProvider: '/',
          otpAuthenticate: (user) => `/otp/authenticate/${user._id}`,
          otpSetup: (user) => `/otp/setup/${user._id}`,
          webAuthnAuthenticate: (user) => `/webauthn/authenticate/${user._id}`,
          webAuthnRegister: (user) => `/webauthn/register/${user._id}`,
        },
      },
      serveStatic: {
        rootPath: join(__dirname, '..', '..', 'client'),
        exclude: ['/api/(.*)'],
      },
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
