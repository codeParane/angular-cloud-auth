import { TestBed } from '@angular/core/testing';

import { ProviderAuthenticationService } from './provider-authentication.service';

describe('ProviderAuthenticationService', () => {
  let service: ProviderAuthenticationService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(ProviderAuthenticationService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
