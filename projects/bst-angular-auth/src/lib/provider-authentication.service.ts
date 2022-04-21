import { Inject, Injectable, OnDestroy, Optional } from '@angular/core';
import { AuthenticationResult, InteractionType, LogLevel, PublicClientApplication } from '@azure/msal-browser';
import { FirebaseApp, getApp, getApps, initializeApp } from '@firebase/app';
import { getAuth, GoogleAuthProvider, signInWithEmailAndPassword, signInWithPopup, signOut, User, UserCredential } from '@firebase/auth';
import { AuthenticationDetails, CognitoUser, CognitoUserPool, CognitoUserSession } from 'amazon-cognito-identity-js';
import { ReplaySubject } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class ProviderAuthenticationService implements OnDestroy {
  providerConfiguration: any;
  accountSubject = new ReplaySubject<IUser>(1);
  activeUser: any;
  application: any;

  constructor(
    @Inject('config') @Optional() public config?: any
  ) {
    this.loadConfiguration(config);
    window.addEventListener('load', async () => {
      this.loadEventListener();
    });
  }

  signIn(): Promise<IUser> {
    try {
      switch (this.providerConfiguration?.provider) {
        case EProviders.AZURE:
          return new Promise((resolve, reject) => {
            this.getApplication().loginPopup().then((authenticationResult: AuthenticationResult) => {
              authenticationResult !== null ? resolve(this.getUser(authenticationResult)): reject();
            });
          });
        case EProviders.FIREBASE:
          return new Promise((resolve, reject) => {
            signInWithPopup(this.getAuthentication(), new GoogleAuthProvider()).then((userCredential: UserCredential) => {
              userCredential !== null ? resolve(this.getUser(userCredential)): reject();
            });
          });
        case EProviders.COGNITO:
          return new Promise((resolve, reject) => {
            try {
              const uri = `${this.providerConfiguration.domainUrl}/login?client_id=${this.providerConfiguration.userPoolWebClientId}&response_type=${this.providerConfiguration.responseType}&scope=aws.cognito.signin.user.admin+email+openid+profile&redirect_uri=${this.providerConfiguration.redirectUrl}`;
              window.location.assign(uri);
              Promise.resolve(this.getUser({}));
            } catch (error) {
              reject(error);
            }
          });
        default:
          throw new Error(`${this.providerConfiguration?.provider} doesnt have an signIn option!`);
      }
    } catch (error) {
      throw new Error(`${this.providerConfiguration?.provider} getting error when signIn, Error : ${error}!`);
    }
  }

  signInWithCredentials(username: string, password: string): Promise<IUser> {
    try {
      switch (this.providerConfiguration?.provider) {
        case EProviders.FIREBASE:
          return new Promise((resolve, reject) => {
            signInWithEmailAndPassword(this.getAuthentication(), username, password).then((userCredential: UserCredential) => {
              userCredential !== null ? resolve(this.getUser(userCredential)) : reject();
            });
          });
          case EProviders.COGNITO:
            const user = new CognitoUser({ Username: username, Pool: this.getApplication() });
            const authenticationDetails = new AuthenticationDetails({ Username: username, Password: password });
            return new Promise((resolve, reject) =>
              user.authenticateUser(authenticationDetails, {
                onSuccess: result => resolve(this.getUser(result)),
                onFailure: err => reject(err)
              })
            );
        default:
          throw new Error( `${this.providerConfiguration?.provider} doesnt have an signInWithCredentials option!`);
      }
    } catch (error) {
      throw new Error( `${this.providerConfiguration?.provider} getting error when signInWithCredentials, Error : ${error}!`);
    }
  }

  signOut(): Promise<void> {
    try {
      switch (this.providerConfiguration?.provider) {
        case EProviders.AZURE:
          return new Promise((resolve, reject) => {
            this.getApplication().logoutRedirect({}).then(() => {
              this.clearActiveUser();
              resolve();
            }).catch((error: any) => {
              reject(error);
            });
          });
        case EProviders.FIREBASE:
          return new Promise((resolve, reject) => {
            signOut(this.getAuthentication()).then(() => {
              this.clearActiveUser();
              resolve();
            }).catch((error) => {
              reject(error);
            });
          });
        case EProviders.COGNITO:
          return new Promise((resolve, reject) => {
            this.getApplication().getCurrentUser().signOut();
            this.clearActiveUser();
            resolve();
          });
        default:
          throw new Error(`${this.providerConfiguration?.provider} doesnt have an signOut option!`);
      }
    } catch (error) {
      throw new Error(`${this.providerConfiguration?.provider} getting error when signOut, Error : ${error}!`);
    }
  }

  getCognitoAccessToken(): string {
    let accessToken = '';
    if(this.providerConfiguration.provider === EProviders.COGNITO && this.providerConfiguration.responseType === 'token' && window.location.href.indexOf("access_token") != -1 ) {
      let urlParams = window.location.hash.replace("#","").split('&');
      urlParams.forEach(param => {
        if(param.startsWith("access_token") && param.length > 1) {
          accessToken = param.replace("access_token=", "")
        }
      });
    }
    return accessToken;
  }

  getActiveUser(): Promise<IUser> {
    return new Promise((resolve, reject) => {
      if (this.retrieveToken() !== '') {
        resolve(this.activeUser);
      }
      reject(`No user is currently logged in the application`);
    });
  }

  interceptorConfigFactory(): unknown {
    switch (this.providerConfiguration?.provider) {
      case EProviders.AZURE:
        const protectedResourceMap = new Map<string, Array<string>>();
        protectedResourceMap.set('https://graph.microsoft.com/v1.0/me', [
          'user.read',
        ]);
        return {
          interactionType: InteractionType.Redirect,
          protectedResourceMap,
        };
      case EProviders.FIREBASE:
      case EProviders.COGNITO:
      default:
        return null;
    }
  }

  guardConfigFactory(): unknown {
    switch (this.providerConfiguration?.provider) {
      case EProviders.AZURE:
        return {
          interactionType: InteractionType.Redirect,
          authRequest: {
            scopes: [`${this.providerConfiguration.auth.clientId}/.default`],
          },
          loginFailedRoute: this.providerConfiguration.login_failed_route,
        };
      case EProviders.FIREBASE:
      case EProviders.COGNITO:
      default:
        return null;
    }
  }
  
  private loadConfiguration(configuration: any){
    if (configuration !== undefined) {
      this.providerConfiguration = this.getConfiguration(configuration);
    }
  }

  private loadEventListener(): Promise<IUser> {
    try {
      switch (this.providerConfiguration?.provider) {
        case EProviders.AZURE:
          return new Promise((resolve, reject) => {
            this.getApplication().handleRedirectPromise().then((authenticationResult: AuthenticationResult) => {
              authenticationResult !== null ? resolve(this.getUser(authenticationResult)): reject();
            });
          });
        case EProviders.FIREBASE:
          return new Promise((resolve, reject) => {
            this.getAuthentication().onAuthStateChanged((user: User | null) => {
              if(user !== null) {
                resolve(this.getUser(user));
              }
            });
          });
        case EProviders.COGNITO:
          return Promise.resolve(this.getUser({}));
        default:
          throw new Error(`${this.providerConfiguration?.provider} doesnt have an load event option!`);
      }
    } catch (error) {
      throw new Error(`${this.providerConfiguration?.provider} getting error when listen the load Event, Error : ${error}!`);
    }
  }

  private getConfiguration(configuration: any): IAzureConfig | IFirebaseConfig | ICognitoConfig {
    try {
      configuration.tokenName = configuration.tokenName !== undefined && configuration.tokenName !== null ? configuration.tokenName : 'auth_token';
      switch (configuration.provider) {
        case EProviders.AZURE:
          return {
            auth: configuration.auth,
            cache: configuration.cache,
            provider: configuration.provider,
            system: {
              loggerOptions: {
                loggerCallback: (level: any, message: any, containsPii: any) => {
                  if (!containsPii) {
                    this.logger(level, message);
                  }
                  return;
                },
              },
            },
          };
        case EProviders.FIREBASE:
        case EProviders.COGNITO:
          return configuration;
        default:
          throw new Error(`no configuration found for given provider: ${this.providerConfiguration?.provider}`);
      }
    } catch (error) {
      throw new Error(`${this.providerConfiguration?.provider} getting error when configure, Error : ${error}!`);
    }
  }

  private logger(level: number, message: string): void {
    switch (level) {
      case LogLevel.Error:
        console.error(message);
        break;
      case LogLevel.Info:
        console.info(message);
        break;
      case LogLevel.Verbose:
        console.debug(message);
        break;
      case LogLevel.Warning:
        console.warn(message);
        break;
      default:
        console.log(message);
        break;
    }
  }

  private getApplication(): PublicClientApplication | FirebaseApp | any {
    try {
      switch (this.providerConfiguration?.provider) {
        case EProviders.AZURE:
          if(this.application === undefined) {
            this.application = new PublicClientApplication(this.providerConfiguration);
          }
          return this.application;
        case EProviders.FIREBASE:
          const ourApp = getApps().filter((app: FirebaseApp) => {
            return app.name === 'auth-app';
          });
          return ourApp.length === 1 ? getApp('auth-app'): initializeApp(this.providerConfiguration, 'auth-app');
        case EProviders.COGNITO:
          if(this.application === undefined) {
            this.application = new CognitoUserPool({
              UserPoolId: this.providerConfiguration.userPoolId,
              ClientId: this.providerConfiguration.userPoolWebClientId
            });
          }
          return this.application;
        default:
          throw new Error(`no application found for provider - ${this.providerConfiguration?.provider}`);
      }
    } catch (error) {
      throw new Error( `${this.providerConfiguration?.provider} getting error when initializing the application, Error : ${error}!`);
    }
  }

  private getAuthentication(): any {
    try {
      switch (this.providerConfiguration?.provider) {
        case EProviders.FIREBASE:
          return getAuth(this.getApplication());
        default:
          throw new Error( `no authentication found for application, provider - ${this.providerConfiguration?.provider}`);
      }
    } catch (error) {
      throw new Error(`${this.providerConfiguration?.provider} getting error when getting auth for the application, Error : ${error}!`);
    }
  }

  private getUser(result: any): IUser {
    const user: IUser = {
      provider: this.providerConfiguration?.provider,
      response: result,
    };
    if (result !== null || result !== undefined) {
      switch (this.providerConfiguration?.provider) {
        case EProviders.AZURE:
          user.userName = result.account.username;
          user.authToken = result.accessToken;
          break;
        case EProviders.FIREBASE:
          if (result.user != null) {
            user.authToken = result.user.accessToken;
            user.userName = result.user.displayName;
          }
          break;
        case EProviders.COGNITO:
          if(this.providerConfiguration.responseType === 'token') {
            user.authToken = this.getCognitoAccessToken();
          };
          const cognitoUser: CognitoUser = this.getApplication().getCurrentUser();
          if(cognitoUser !== null) {
            cognitoUser.getSession((error: Error | null, session: CognitoUserSession): any => {
              if(error){
                throw error;
              } else {
                user.authToken = session.getAccessToken().getJwtToken();
              }
            });
            user.userName = cognitoUser.getUsername();
            user.response = cognitoUser;
          }
      }
      if (user !== null) {
        this.accountSubject.next(user);
        this.persistToken(user.authToken || '');
      }
    }
    this.activeUser = user;
    return user;
  }

  private persistToken(token: string): void {
    localStorage.setItem(this.providerConfiguration.tokenName, token);
  }

  private retrieveToken(): string | null {
    return localStorage.getItem(this.providerConfiguration.tokenName);
  }

  private clearActiveUser(): void {
    const emptyUser: IUser = {
      provider: this.providerConfiguration?.provider,
    };
    this.accountSubject.next(emptyUser);
    this.accountSubject.unsubscribe();
    this.activeUser = null;
    localStorage.removeItem(this.providerConfiguration.tokenName);
  }

  ngOnDestroy(): void {
    this.clearActiveUser();
  }

}

export interface IFirebaseConfig {
  provider?: EProviders;
  apiKey: string;
  authDomain: string;
  databaseURL?: string;
  projectId: string;
  storageBucket: string;
  messagingSenderId: string;
  appId: string;
  measurementId: string;
  redirectUri?: string;
  login_failed_route?: string;
  login_route?: string;
  tokenName?: string;
}

export interface IAzureConfig {
  provider?: EProviders;
  auth: {
    clientId: string;
    redirectUri: string;
    authority: string;
  },
  cache: {
    cacheLocation: string;
    storeAuthStateInCookie: boolean;
  },
  system?: any;
  loginFailedRoute?: string;
  loginRoute?: string;
  responseType?: string;
  tokenName?: string;
}

export interface ICognitoConfig {
  provider?: EProviders;
  userPoolId: string;
  userPoolWebClientId: string;
  domainUrl: string;
  redirectUrl: string;
  loginFailedRoute?: string;
  loginRoute?: string;
  responseType: string;
  tokenName?: string;
}

export interface IUser {
  provider: string;
  userName?: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  authToken?: string;
  response?: any;
}

export enum EProviders {
  AZURE,
  FIREBASE,
  COGNITO,
}
