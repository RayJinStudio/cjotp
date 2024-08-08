package cjotp

import std.time.*

import crypto.digest.*

public class TOTP <: OTP {
    /***
    * Handler for time-based OTP counters.
    ***/

    let interval: Int64

    public init(
        secret: String,
        digits!: Int64 = 6,
        digest!: HashType = HashType.SHA512, // only support SHA512 on v0.53.4
        name!: Option<String> = None,
        issuer!: Option<String> = None,
        interval!: Int64 = 30
    ) {
        /***
        * param secret: secret in base32 format
        * param initialCount: starting HMAC counter value, defaults to 0
        * param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        * param digest: digest function to use in the HMAC (expected to be SHA1)
        * param name: account name
        * param issuer: issuer
        ***/

        super(secret, digits: digits, digest: digest, name: name, issuer: issuer)
        this.interval = interval
    }

    public func at(timeZone: TimeZone, counterOffset!: Int64 = 0) {
        return this.generateOtp(this.timeCode(timeZone: timeZone) + counterOffset)
    }

    public func now(): String {
        /***
        * Generate the current time OTP
        * returns: OTP value
        ***/
        return this.generateOtp(this.timeCode())
    }

    public func verify(
        otp: String, 
        timeZone!: Option<TimeZone> = None, 
        vaildWindow!: Int64 = 0
    ): Bool {
        /***
        * Verifies the OTP passed in against the current time OTP.
        * param otp: the OTP to check against
        * param timeZone: Time to check OTP at (defaults to now)
        * param validWindow: extends the validity to this many counter ticks before and after the current one
        * returns: True if verification succeeded, False otherwise
        ***/

        let timeZoneVal: TimeZone = if (let Some(value) <- timeZone) {
            value
        } else {
            TimeZone.Local
        }

        if (vaildWindow != 0) {
            for(i in -vaildWindow..vaildWindow) {
                if (this.at(timeZoneVal, counterOffset: i) == otp) {
                    return true
                }
            }
            return false
        }

        return otp == this.at(timeZoneVal)
    }

    public func provisioningUrl(
        name!: Option<String> = None,
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
            issuer: if (let Some(issuerVal) <- issuer) {
                issuerVal
            } else {
                this.issuer
            },
            algorithm: this.digestType.toString(),
            digits: this.digits,
            period: this.interval,
            image: image
        )
    }

    private func timeCode(timeZone!: TimeZone = TimeZone.Local): Int64 {
        /***
        * Accepts either a timezone naive as argument and returns the
        * corresponding counter value (timecode).
        ***/
        let now = DateTime.now(timeZone: timeZone).toUnixTimeStamp().toSeconds()
        return now / this.interval
    }
}