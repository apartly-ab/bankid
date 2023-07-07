import {describe, it} from 'mocha'
import {IPollRequest, createJunk, verifyJunk} from '../../src/strategies/PollingStrategy'
import { expect } from 'chai';
import { randomBytes } from 'crypto';

describe('PollingStrategy', () => {
    it('should be able to verify junk that it created itself', () => {
        const qrStartSecretEncryptionKey = randomBytes(32).toString('hex');
        const orderRefHashKey = randomBytes(32).toString('hex');
        const junkInput = {
            orderRef: "123",
            nextPollTime: 123,
            orderRefHashKey,
            qrStartSecretEncryptionKey,
            retriesLeft: 123,
            qrStartSecret: "123",
            qrStartToken: "123",
            startTime: 123,
        };
        const junk = createJunk(junkInput);
        const order : IPollRequest = {
            orderRef: "123",
            nextPollTime: 123,
            ipAddress: "123",
            junk: junk,
            qrStartToken: "123",
            retriesLeft: 123,
            startTime: 123,            
        }            
        const verified = verifyJunk({
            order,
            orderRefHashKey,
            qrStartSecretEncryptionKey,
        });

        expect(verified).to.not.be.null;

    })
})