# RASP_DEMO
一个简易RASP的开发过程
## 写在前面
  自2014年Gartner在应用安全报告里提出了应用自我保护技术（Runtime Application Self-Protection，简称RASP）的概念，RASP已经发展了9个年头了，国内外也有不少企业都开发了自己的RASP，在国内有百度的[ OpenRasp ]: https://github.com/baidu/openrasp
  OpenRasp是一个非常优秀的开源Rasp项目，但是对于像我这样平时没系统写过代码的新手而言，OpenRasp的架构较复杂，通过看OpenRasp代码学习Rasp技术时间较长。所以我将我自己零散的学习记录进行整理，方便像我这样的新手也能轻易了解Rasp，并制作一些小项目。
## 问题
### RASP_ZERO生成方式
  使用maven打开本项目:
使用maven插件assembly 打包项目(与普通的打包相比，assembly会将项目中导入的依赖一起打包进生成的jar包)
![6O`HYJZ M{1QC9H8DK4W~1E](https://user-images.githubusercontent.com/94785056/234197728-9831b9af-9f3b-4bfd-8d7e-a86da9d487ab.png)
target目录下，RASP_zero-1.0-SNAPSHOT-jar-with-dependencies.jar即为我们需要的jar包。
![6O`HYJZ M{1QC9H8DK4W~1E](https://user-images.githubusercontent.com/94785056/234198126-ea6993ce-b1c1-43f5-95ac-6ab981223ee4.png)


