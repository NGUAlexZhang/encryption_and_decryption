# 自制的C++加解密工具demo

## 开发环境
gcc 13.2.0

GNU Make 4.3

GLIBC 2.39

ubuntu 24.04

## 编译安装
下载源代码:
``` shell
git clone https://github.com/NGUAlexZhang/encryption_and_decryption.git
```

编译:
``` shell
make all
```

安装(请使用管理员权限运行以下指令):
``` shell
make install
```

## 使用
安装后可在命令行运行az-rsa、az-aes、az-sha分别用于非对称加密、对称加密、哈希运算。

可使用 xxx -h 如 az-rsa -h 的指令查看其对应的使用方法。

## TODO：
* 交叉编译
* 更强的操作系统兼容性