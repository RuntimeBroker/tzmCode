## IDA特征码提取插件

## 文件介绍

tzmCode.py

~~~
 升级成插件IDA Pro 9 原来是python2写的 现在升级到python39
~~~

searchCode.h
searchCode.c

IDA插件配合这俩使用



## 使用说明

### 1、安装tzmCode.py IDA插件

安装`tzmCode.py`到IDA9当中，成功则在plugins里会显示插件，以及在底下的OutPut窗口显示

![image-20250112173341342](https://pic.gitlab.cx/gh/RuntimeBroker/pic-bed/img/2025/01/12/OnNFgh58XaeDxKrGgitm1736674421507.png)

![image-20250112173445462](https://pic.gitlab.cx/gh/RuntimeBroker/pic-bed/img/2025/01/12/uhW72bA7xEqG8yvWYGyv1736674485614.png)

### 2、将配套的工具添加进入VS里

添加到你的vs项目当中
![image-20250112172755138](https://pic.gitlab.cx/gh/RuntimeBroker/pic-bed/img/2025/01/12/gyJHi9OVwjYfXcdtflfR1736674330042.png)

### 3、函数使用

~~~c
PLONG_PTR funAddr = searchCode("ntkrnlpa.exe", "8B*****85C974*8D7D*ABAB894D*8D45*E8****B8****", "PAGEVRFY", -0x2a);

第1个参数：模块名字
第2个参数：特征码
第3个参数：函数在哪个节，这填写节的名字
第4个参数：距离当前函数起始位置的offset 这里是填写成负的偏移
~~~

![image-20250112174007339](https://pic.gitlab.cx/gh/RuntimeBroker/pic-bed/img/2025/01/12/JwIBed65ihR8oWMS5YBP1736674807516.png)

当前的函数offset：0x2a

那么第4个参数就写成：-0x2a

## 效果图

![image-20250112173204883](https://pic.gitlab.cx/gh/RuntimeBroker/pic-bed/img/2025/01/12/WPpbXCOO4ekHZSwA2XWd1736674325369.png)

![image-20250112174105081](https://pic.gitlab.cx/gh/RuntimeBroker/pic-bed/img/2025/01/12/lyWe9HOw7qq36SKMtmKx1736674865194.png)