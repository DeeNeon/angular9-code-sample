import {HttpErrorResponse, HttpHandler, HttpInterceptor, HttpRequest} from '@angular/common/http';
import {from, throwError} from 'rxjs';
import {Injectable, Injector} from '@angular/core';
import * as Raven from 'raven-js';
import {environment} from '../../../environments/environment';
import {AppStateService} from './app-state.service';
import {AuthService} from '../../core/auth/auth.service';
import {LocalStorageService} from 'angular-2-local-storage';
import * as moment from 'moment';
import {catchError, switchMap, takeUntil, tap} from 'rxjs/operators';
import {set} from './idb-keyval';

@Injectable()
export class TokenInterceptor implements HttpInterceptor {
  authService;
  moment: any = moment;
  refreshTokenInProgress = false;
  ignoredPaths: any = ['/activate', '/reset-password'];

  constructor(private appStateService: AppStateService,
              private localStorageService: LocalStorageService,
              private injector: Injector) {};

  sendDataToSentry(error: any) {
    const user = this.localStorageService.get('currentUser');
    const errorInfo: any = {
      code: error && error.status,
      error: error,
      account: user || 'no user in session',
      env: environment.name,
      errorMessage: error && error.message,
      apiUrl: error && error.url,
      errorHint: 'API response returns a non success request.'
    };

    const isErrorOrErrorEvent = (param) => {
      return Object.prototype.toString.call(param) === '[object Error]'
        || Object.prototype.toString.call(param) === '[object ErrorEvent]';
    };

    const _error = error.originalError || error;
    if (!isErrorOrErrorEvent(_error)) {
      Raven.captureMessage(_error.error || _error);
    }

    // goldfish code means 'Authorization Required or expired'
    if (error.error && error.error.code &&
      error.error.code !== 'goldfish' && error.error.code.indexOf('NotAuthorizedException') === -1) {
      console.error('Authorization required or expired: ', error);
      Raven.captureException(errorInfo);
    }
  }

  intercept(request: HttpRequest<any>, next: HttpHandler) {
    this.authService = this.injector.get(AuthService);
    const tokenStartTime = this.localStorageService.get('token_start_time');
    const isIndexOf = this.ignoredPaths.filter(path => window.location.pathname.indexOf(path) > -1);
    if (!tokenStartTime && !isIndexOf.length) {
      this.authService.logout();
    }

    return from (this.authService.getAuthorizationHeader(request)).pipe(
      takeUntil(this.appStateService.onCancelPendingRequests()),
      switchMap((newRequest: any) => {
        request = newRequest;

        return next.handle(request).pipe(
          tap(() => {
            const startTime = tokenStartTime && moment(tokenStartTime);
            const now = moment();
            const diff = startTime && moment(now).diff(startTime);
            const duration = this.moment.duration(diff).minutes();

            if (duration > 15 && !this.refreshTokenInProgress) {
              this.refreshTokenInProgress = true;
              this.localStorageService.set('token_start_time', moment().format());
              this.authService.refreshToken().subscribe((res: any) => {
                this.refreshTokenInProgress = false;

                if (res.data) {
                  set('token', res.data.token);
                } else {
                  this.authService.logout();
                }
              });
            }
          }),
          catchError(error => {
            if (error instanceof HttpErrorResponse) {
              this.refreshTokenInProgress = false;

              if (error.status === 401 || error.status === 403 || !error.status || error.status === 504) {
                this.authService.logout();
              } else {
                // TODO: this is handled by SentryErrorHandler
                this.sendDataToSentry(error);
              }

              return throwError(error);
            }
          })
        );
      }));
  }
}
