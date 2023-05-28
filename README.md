# 基于机器学习的网络流量分析审计系统 - TrafficCat

![flowchart](./demo/flowchart.png)

## 文件结构
* `build/`: **网络嗅探器编译目录**
    * `bin`: 可执行文件目录
        * `clsniff`: 嗅探器可执行文件(CLI 模式)
        * `trafficat`: 嗅探器可执行文件(GUI 模式)
    * `build.sh`: GUI 模式编译脚本
    * `trafficat.pro`: GUI 模式工程文件
    * `clsniff.sh`: CLI 模式编译脚本
    * `clsniff.pro`: CLI 模式工程文件
* `data/`: **数据存放目录**
    * `extractor.txt`: 提取的特征文件
    * `label.txt`: 输出的标签文件
    * `traffic.pcap`: 嗅探器输出的流量文件
    * `traffic.json`: 流量文件(json 格式)
* `demo/`: **演示目录**
    * `images/`: 截屏图片目录
    * `flowchart.png`: 系统架构图
    * `TrafficCat.pptx`: 系统演示 PPT
    * `Run_in_Docker.mp4`: Docker 运行演示视频
    * `Run_in_Ubuntu.mp4`: Ubuntu 运行演示视频
* `docs/`: **文档目录**
    * `需求分析文档.pdf`: 需求分析文档
    * `设计文档.pdf`: 设计文档
    * `测试文档.pdf`: 测试文档
    * `部署文档.pdf`: 部署文档
* `kdd/`: **特征提取器及 NTML 模型目录**
    * `inferfence/`: 模型目录
        * `encoder/`:编码器
        * `model/`: 模型
        * `nomalize/`: 归一化
        * `main.py`: 主程序
        * `preprocess.py`: 预处理程序
    * `kdd99_cmake/`: 特征提取器目录
        * `cmake/`: cmake
        * `src/`: 源代码
        * `doc/`: 相关文档
        * `CMakeLists.txt`: cmake 文件
        * `README.md`: 特征提取器说明文档
    * `kdd99extractor`: 特征提取器可执行文件
* `minio/`: **数据库目录**
    * `extractor_tmp/`: 特征临时文件目录
    * `json_tmp/`: 流量临时文件目录
    * `label_tmp/`: 标签临时文件目录
    * `clean.py`: 清理脚本
    * `demo.py`: 演示脚本
    * `dockerfile`: dockerfile
    * `download.py`: 下载脚本
    * `minio_install.md`: 安装说明文档
    * `upload.py`: 上传脚本
* `src/`: **网络嗅探器源代码目录**
    * `utils/` - 工具目录
        * `utils.h` - 工具函数定义
        * `utils.cpp` - 工具函数实现
        * `hdr.h` - 包头定义文件
    * `catch.cpp`: Catch 包实现
    * `catch.h`: Catch 包定义
    * `cl_main.cpp`: CLI 主函数
    * `cl_sniff.cpp`: CLI Sniff 功能实现
    * `devwindow.cpp`: 设备窗口实现
    * `devwindow.h`: 设备窗口定义
    * `filter.cpp`: 过滤器实现
    * `filter.h`: 过滤器定义
    * `main.cpp`: GUI 主函数
    * `mainwindow.cpp`: 主窗口实现
    * `mainwindow.h`: 主窗口定义
    * `sniffer.cpp`: Sniff 功能实现
    * `sniffer.h`: Sniff 功能定义
    * `view.cpp`: 视图实现
    * `view.h`: 视图定义
* `ui`: **网络嗅探器UI界面目录**
    * `mainwindow.ui`: 主窗口 UI 文件
* `web`: **网页目录**
    * `dashboard.py`: 仪表盘代码
    * `requirements.txt`: 依赖文件
* `all.sh`: 加载之前所有文件脚本
* `run.sh`: 运行脚本
* `README.md`: **说明文档**

## DOCKER 封装获取方式
* [交大云盘下载](https://jbox.sjtu.edu.cn/l/U1Mduw)
* 从 Docker hub 拉取：docker pull futuresjtu/traffic-v6


## 小组成员及贡献度

郑宇森 520021911173 - 16.66%

王鑫   520021910700 - 16.66%

姜来   520021910159 - 16.66%

韩志鹏 520021911273 - 16.66%

赵鸿宇 520021910734 - 16.66%

喻路稀 520030910078 - 16.66%
