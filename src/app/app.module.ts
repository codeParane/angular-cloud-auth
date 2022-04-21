import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { EProviders } from 'projects/bst-angular-auth/src/public-api';

import { AppComponent } from './app.component';

@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule
  ],
  providers: [
       {
      provide: 'config',
      useValue: {
        provider: EProviders.COGNITO,
        userPoolId: "eu-west-1_Px1kN5J5V",
        userPoolWebClientId: '4g8pch764tjqm0rumc170rjbj1',
        domainUrl: 'https://bst-elementry-dev.auth.eu-west-1.amazoncognito.com/',
        redirectUrl: 'http://localhost:4200/authentication/login',
        responseType: 'token',
      }
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
