# The Cangjie One-Time Password Library
API设计参考如下项目:

https://github.com/pyauth/pyotp

用户手册请参考：[用户手册](制作中)

## 特性
1. 支持HOTP和TOTP两种算法的密码生成
2. 对密码进行校验
3. 生成 otpauth:// 链接，方便用户扫码添加（支持Google Authenticator、Authy或其他兼容APP）

## 待完善功能
1. 目前仓颉仅支持HMAC-SHA512算法（后续会支持其他算法）
2. secret key的base32解码算法未实现，需要解码后传入（正在实现）