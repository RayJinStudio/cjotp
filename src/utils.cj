package cjotp

import std.collection.*

import encoding.url.*
import crypto.digest.*

func buildUrl(
    secret: String,
    name: String,
    initialCount!: Option<Int64> = None,
    issuer!: Option<String> = None,
    algorithm!: Option<String> = None,
    digits!: Option<Int64> = None,
    period!: Option<Int64> = None,
    image!: Option<String> = None
): String {
    /***
    * Returns the provisioning URI for the OTP; works for either TOTP or HOTP.
    *
    * This can then be encoded in a QR Code and used to provision the Google
    * Authenticator app.
    *
    * For module-internal use.
    *
    * See also:
    *     https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    *
    * param secret: the hotp/totp secret used to generate the URI
    * param name: name of the account
    * param initial_count: starting counter value, defaults to None.
    *     If none, the OTP type will be assumed as TOTP.
    * param issuer: the name of the OTP issuer; this will be the
    *     organization title of the OTP entry in Authenticator
    *param algorithm: the algorithm used in the OTP generation.
    *　param digits: the length of the OTP generated code.
    * param period: the number of seconds the OTP generator is set to
    *    expire every code.
    * param image: optional logo image url
    * returns: provisioning uri
    ***/
    let otpType: String = if (let Some(_) <- initialCount) {
        "hotp"
    } else {
        "totp"
    }
    let urlArgs: Form = Form()
    urlArgs.add("secret", secret)

    var label: String = name
    if (let Some(issuerVal) <- issuer) {
        label = issuerVal + ":" + label
        urlArgs.add("issuer", issuerVal)
    }

    if (let Some(initialCountVal) <- initialCount) {
        urlArgs.add("counter", "${initialCountVal}")
    }

    if (let Some(algorithmVal) <- algorithm) {
        if (algorithmVal != "SHA1") {
            urlArgs.add("algorithm", algorithmVal.toAsciiUpper())
        }
    }

    if (let Some(digitsVal) <- digits) {
        if (digitsVal != 6) {
            urlArgs.add("digits", "${digitsVal}")
        }
    }

    if (let Some(periodVal) <- period) {
        if (periodVal != 30) {
            urlArgs.add("period", "${periodVal}")
        }
    }

    if (let Some(imageVal) <- image) {
        if (imageVal.startsWith("https")) {
            urlArgs.add("image", imageVal)
        } else {
            throw IllegalArgumentException("Image URL must start with 'https'")
        }
    }

    let url: String = "otpauth://${otpType}/${label}?${urlArgs.toEncodeString()}"
    return url
}