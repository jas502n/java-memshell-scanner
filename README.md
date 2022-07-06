[*] 2022-07-06 add tomcat-memshell-scanner jspx

<img width="1771" alt="image" src="https://user-images.githubusercontent.com/16593068/177464901-6fc57fc5-bb15-46c6-bc26-dce038512d21.png">

## 0x01 简介
通过jsp脚本扫描并查杀各类中间件内存马，比Java agent要温和一些。

## 0x02 截图
![Tomcat内存马扫描结果展示](doc/tomcat-memshell-scanner.png)

增加Listener型内存马检测，如果不存在Listener则不显示该项

![Tomcat内存马扫描结果展示](doc/listener.png)

## 0x03 更多
[Filter/Servlet型内存马的扫描抓捕与查杀](https://gv7.me/articles/2020/filter-servlet-type-memshell-scan-capture-and-kill/)
