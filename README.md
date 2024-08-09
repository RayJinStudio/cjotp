# The Cangjie One-Time Password Library
API设计参考如下项目:

https://github.com/pyauth/pyotp

## 特性
1. 支持HOTP和TOTP两种算法的密码生成
2. 对密码进行校验
3. 生成 otpauth:// 链接，方便用户扫码添加（支持Google Authenticator、Authy或其他兼容APP）

## 待完善功能
1. 目前仓颉仅支持HMAC-SHA512算法（后续会支持其他算法）
2. secret key的base32解码算法未实现，需要解码后传入（正在实现）

## 使用方法
#### 1. 导入库
~~~cangjie
import cjotp.*
~~~

#### 2. 生成当前时间TOTP密码
传入secret key，base32解码后的字符串
~~~cangjie
tPassword = TOTP(key).now()
~~~

#### 3. 生成HOTP密码
传入counter参数，表示当前计数器的值
~~~cangjie
hPassword = HOTP(key).at(counter)
~~~

#### 4. 验证密码
传入用户输入的密码
~~~cangjie
if(TOTP(key).verify(tpassword)) {
    println("Password is valid")
} else {
    println("Password is invalid")
}
~~~

#### 5. 生成otpauth://链接
~~~cangjie
TOTP(key).provisioningUrl(name: "test", issuer: "issuer")
~~~

#### 示例
~~~cangjie
import cjotp.*

import std.sync.*
import std.time.*

main(): Int64 {
    let key: String = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"

    let tpassword = TOTP(key).now()
    let hpassword = HOTP(key).at(0)
    println("TOTP: ${tpassword}")
    println("HOTP: ${hpassword}")

    // sleep 5s
    println("Sleep 5s")
    sleep(Duration.second * 5)
    if(TOTP(key).verify(tpassword)) {
        println("After 5s Password is valid")
    } else {
        println("After 5s Password is invalid")
    }

    // sleep 25s
    println("Sleep 25s")
    sleep(Duration.second * 25)
    if(TOTP(key).verify(tpassword)) {
        println("After 25s Password is valid")
    } else {
        println("After 25s Password is invalid")
    }


    if(TOTP(key).verify(tpassword, vaildWindow: 1)) {
        println("After 25s: vaildWindow 1 Password is valid")
    } else {
        println("After 25s: vaildWindow 1 Password is invalid")
    }

    // provisioning url
    print(TOTP(key).provisioningUrl(name: "test", issuer: "issuer") + "\n")
    return 0
}
~~~


