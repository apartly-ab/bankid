import {describe, it} from 'mocha';
import {expect} from 'chai';
import { SinonStubbedInstance } from 'sinon';
import CognitoAuthClient from '../../src/authClients/CognitoClient';
import sinon from 'sinon';

/**
describe('CognitoAuthClient', () => {
    let client: SinonStubbedInstance<CognitoAuthClient>;
    beforeEach(() => {
        client = sinon.createStubInstance(CognitoAuthClient);
        client.run.resolves({
            IdToken: "idToken",
            AccessToken: "accessToken",
            RefreshToken: "refreshToken",
            ExpiresIn: 3600,
            TokenType: "Bearer",
            NewDeviceMetadata: {
                DeviceGroupKey: "deviceGroupKey",
                DeviceKey: "deviceKey"
            }
        });
    })
    it('should return an authentication result', async () => {
        
})
*/