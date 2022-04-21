import { Component } from '@angular/core';
import { ProviderAuthenticationService } from 'bst-angular-auth';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'app12';

  constructor(
    private a: ProviderAuthenticationService
  ){

  }





  sign(){

    this.a.signIn().then(res => {
      console.log(res);
      
    })

  }
}
