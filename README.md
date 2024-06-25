# evtReader
windows system log file(.evt XP/2000) extract

介绍 Introdction  
由于在NT/Win2000/XP/Server 2003版本的操作系统中，操作系统日志是.evt格式；在Vista/Win7/Win8//Win10/Server 2008/Server 2012等版本的操作系统中，操作系统日志升级为.evtx格式，两种格式并不通用。当.evt格式的操作系统日志在WIN7/10中打开时，日志的时间无法被正确解析。  
In the NT/Win2000/XP/Server 2003 operating system, operating system logs are .evt format. In Vista/Windows 7 / doing / / Win10 / Server 2008 / Server 2012 version of the operating system, operating system log upgraded to .evtx format, two kinds of format is not universal. When operating system logs in .evt format are opened in Windows 7/10, the log time cannot be parsed correctly.  
pywin32库的win32evtlog模块提供的OpenBackupEventLog函数可以读取离线的日志文件。通过测试发现该方法仍然只能打开.evt文件。  
The OpenBackupEventLog function provided by the win32evtlog module of the pywin32 library can read offline log files. Tests show that this method still only opens.evt files.
Evtx库只能解析.evtx格式的文件，如果需要对WIN7/WIN10等本地操作系统日志进行监控时，使用该库是一个不错的选择。但是这个库无法解析.evt文件。  
Evtx library can only parse .evtx format files, if you need to monitor the local operating system logs such as WIN7/WIN10, use the library is a good choice. But this library cannot parse .evt files.  
当前面的方法都没办法解决我们的问题时，我们可以尝试对.evt文件的二进制格式直接进行解析。.evt文件格式描述可以参考如下文档：
https://github.com/libyal/libevt/blob/main/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc
When none of the current methods can solve our problem, we can try to parse the binary format of the.evt file directly. For the description of the.evt file format, see the following documents:
https://github.com/libyal/libevt/blob/main/documentation/Windows%20Event%20Log%20(EVT)%20format.asciidoc
