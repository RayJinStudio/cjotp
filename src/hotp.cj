package cjotp

import crypto.digest.*

public class HOTP <: OTP {
    /***
    * Handler for HMAC-based OTP counters.
    ***/

    let initialCount: Int64

    public init(
        secret: String,
        digits!: Int64 = 6,
        digest!: HashType = HashType.SHA512, // only support SHA512 on v0.53.4
        name!: Option<String> = None,
        issuer!: Option<String> = None,
        initialCount!: Int64 = 0
    ) {
        /***
        * param secret: secret in base32 format
        * param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        * param digest: digest function to use in the HMAC (expected to be SHA1)
        * param name: account name
        * param issuer: issuer
        * param initialCount: initial counter value
        ***/

        super(secret, digits: digits, digest: digest, name: name, issuer: issuer)
        this.initialCount = initialCount
    }

    public func at(counter: Int64) {
        return this.generateOtp(this.initialCount + counter)
    }

    public func verify(otp: String, counter: Int64): Bool {
        /***
        * Verifies the OTP passed in against the current counter OTP.
        * param otp: the OTP to check against
        * param counter: the OTP HMAC counter
        ***/
        return otp == this.at(counter)
    }

    public func provisioningUrl(
        name!: Option<String> = None,
        initialCount!: Int64 = 0,
        issuer!: Option<String> = None,
        image!: Option<String> = None
    ): String {
        /***
        * Returns the provisioning URI for the OTP.  This can then be
        * encoded in a QR Code and used to provision an OTP app like
        * Google Authenticator.
        *
        * See also:
        *     https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        ***/
        return buildUrl(
            this.secret,
            if (let Some(nameVal) <- name) {
                nameVal
            } else {
                this.name
            },
            initialCount: initialCount,
            issuer: if (let Some(issuerVal) <- issuer) {
                issuerVal
            } else {
                this.issuer
            },
            algorithm: this.digestType.toString(),
            digits: this.digits,
            image: image
        )
    }
}