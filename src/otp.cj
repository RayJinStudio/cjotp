package cjotp

import std.binary.*
import std.crypto.digest.*

import crypto.digest.*

import std.math.pow

public open class OTP {
    /**
    * Base class for OTP handlers.
    **/

    let secret: String
    let digits: Int64
    let digestType: HashType
    let name: String
    let issuer: Option<String>

    public init(
        secret: String,
        digits!: Int64 = 6,
        digest!: HashType = HashType.SHA512, // only support SHA512 on v0.53.4
        name!: Option<String> = None,
        issuer!: Option<String> = None
    ) {
        this.secret = secret
        this.digits = digits
        if (digits > 10) {
            throw IllegalArgumentException("digits must be no greater than 10")
        }
        this.digestType = digest
        this.name = if(let Some(nameVal) <- name) {
            nameVal
        } else {
            "Secret"
        }
        this.issuer = issuer
    }

    private static func int2ByteArray(
        i: Int64, 
        padding!: Int64 = 8
    ): Array<Byte> {
        /**
        * Turns an integer to the OATH specified
        * bytestring, which is fed to the HMAC
        * along with the secret
        **/

        var result: Array<Byte> = Array<Byte>(padding, item: 0)
        i.writeBigEndian(result)
        return result
    }

    private func byteSecret() {
        /**
        * Turns the secret into a byte array
        **/

        // TODO: base32 decode
        return this.secret.toArray()
    }

    public func generateOtp(input: Int64): String {
        /**
        * param input: the HMAC counter value to use as the OTP input.
        *     Usually either the counter, or the computed integer based on the Unix timestamp
        **/

        if(input < 0) {
            throw IllegalArgumentException("input must be positive integer")
        }
        let hmac = HMAC(this.byteSecret(), this.digestType)
        let hmac_hash: Array<Byte> = digest(hmac, int2ByteArray(input))
        let offset: Int64 = Int64(hmac_hash[hmac_hash.size - 1] & 0xf)
        var code: Int64 = (
            Int64(hmac_hash[offset] & 0x7F) << 24 | 
            Int64(hmac_hash[offset + 1] & 0xFF) << 16 |
            Int64(hmac_hash[offset + 2] & 0xFF) << 8 |
            Int64(hmac_hash[offset + 3] & 0xFF)
        )
        code = 10_000_000_000 + (code % Int64(pow(Float64(10),digits)))
        let strCode: String = "${code}"
        return strCode[(strCode.size - this.digits)..strCode.size]
    }
}