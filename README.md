# Netriver-TCP-Protocol-LAB

计网概论lab tcp协议部分，完善确认号逻辑

netriver 实验的 TCP 协议，网上很多代码的在实现 socket API 时就不再检查服务器发回来的 TCPHead 的 ack number 跟 seq number（或者检查方法错误）。

主要完善了 socket API 中的确认号逻辑，更好理解 TCP 握手逻辑。

改逻辑的清晰表述参考：https://blog.csdn.net/weijuqie0697/article/details/81362158
