# S-AES 算法实验

信息安全导论课外作业2。使用 Python 标准库实现 S-AES，并提供 Tkinter 图形界面。

小组成员：季冬阳（2024501）、张琨奕（20240541）。

## 实验报告与文档

- [实验报告](reports/实验报告.md)
- [用户指南](docs/用户指南.md)
- [开发手册与接口](docs/开发手册.md)
- [原始测试结果](reports/results/)
- [实验截图](https://github.com/pinggaozhanshi/s-aes/releases/tag/report-assets-2026-10-29)

## 启动

需要 Python 3.10 或更新版本，并安装 Python 自带的 Tkinter。无需第三方 Python 包。

```powershell
git clone https://github.com/pinggaozhanshi/s-aes.git
cd s-aes
python main.py
```

Windows 也可双击 `start.bat`。本次测试环境为 Windows 11、Python 3.13.2、Tk 8.6。

## 功能

| 页面 | 功能 |
| --- | --- |
| 基础加解密 / 字符串 | 16位HEX/BIN分组、ASCII字符串、轮密钥与计算轨迹 |
| 双重 / 三重加密 | 32位EE、48位EEE及逆向解密 |
| 中间相遇攻击 | 完整枚举两个16位子密钥空间、多对数据过滤、取消与候选CSV导出 |
| CBC / 篡改实验 | 随机16位IV、长消息加解密、异或或替换密文分组后的结果比较 |

状态按列排列；基础分组不填充。ASCII使用大端两字节分组和PKCS#7填充，IV独立传递。
组合密钥从左到右拆分，双重为 `E_K2(E_K1(P))`，三重为 `E_K3(E_K2(E_K1(P)))`。

## 测试

```powershell
python -m unittest discover -s tests -v
python tools/run_experiments.py
```

测试覆盖教材逐步向量、分组与密钥空间往返、独立矩阵实现核对、输入边界、ASCII、EE/EEE、完整中间相遇搜索、CBC篡改传播和Tk回调。GUI测试需要可用的桌面及Tk。

已保存31项本地测试的运行记录。样例攻击使用1、2、3对明密文时，候选数分别为65,046、3、1。
季冬阳与张琨奕使用不同程序完成了同组样例对照；另一小组参与的课程互测仍待完成。

## 截图与数据

8张实验截图存放在GitHub Release中，报告直接引用其公开地址；仓库保存来源、参数和SHA256清单。
源代码下载后可以打开GUI并复现实验，查看在线报告中的截图需要网络连接。

S-AES是教学算法，16位分组和密钥不适合保护实际敏感数据。
