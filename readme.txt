目前WAF只支持Windows平台
安装：
    1，使用本软件最好直接在OpenResty官网下载OpenResty，OpenResty自身带有Nginx。
    2，将该WAF下载到OpenResty的lua目录下，解压即可。
    3，日志读写的文件必须给与相应的权限。

使用说明：
    1，需要在nginx.conf文件中包含WAF解压出来的conf中的waf.conf文件
    2，需要在waf/conf路径下的config.lua文件中修改日志存储位置以及规则存储位置

配置说明：
    是否开启白名单IP检查
    _M.IPWhiteCheck = "on"

    是否开启黑名单IP检查
    _M.IPBlockCheck = "on"

    是否开启白名单URl检查
    _M.WhiteUrlCheck = "on"

    是否开启黑名单URl检查
    _M.BlockUrlCheck = "on"

    是否开启参数检查
    _M.ArgCheck = "on"

    是否开启useragent检查
    _M.UserAgentCheck = "on"

    是否开启cookie检查
    _M.CookieCheck = "on"

    是否开启CC攻击防御
    _M.CCDenyCheck = "on"

    是否开启POST上传检查
    _M.PostCheck = "on"

    CC攻击的速率（次数/秒）
    _M.CCRate = "100/60"

    IP访问的速率（次数/秒）
    _M.Count = "100/60"

    是否开启日志记录
    _M.LogCheck = "on"

    疑似对攻击网站的行为的封禁时间(单位：秒)
    _M.BlockTime = "1800"

    是否开启错误页面重定向
    _M.Redirect = "on"

    是否开启某些关键路径只有某些IP可以访问
    _M.AccessControl = "on"

    是否开启XSS检测
    _M.XSSCheck = "on"

    是否开启数据库存储
    _M.MysqlLog = "on"

    以上处于waf/conf/config.lua配置文件中，若是配置文件中问on的表示该功能启用，网站禁止访问时间以秒为单位
    可以自己设置，同样的检测CC攻击和IP访问频率以（次数/秒）设置

规则说明：
    规则配置文件在waf/rule文件夹下

    args.rulel里面的规则用于GET请求时检查参数和参数名是否正确
    block.rule里面的规则用于检测GET请求时用户访问的URL是否是敏感信息
    cookies.rule里面的规则用于检测在请求头中的cookie是否包含的扫描器特征值
    filenameExt.rule里面的规则用于检测上传的文件扩展名是否合法
    IPBlocklist.rule里面的规则是禁止访问的IP
    IPWhitelist.rule里面的规则是可以不需要进行权限控制和黑名单检测的IP
    manage_IP.json里面的规则用于权限管理检测
    post.rule里面的规则用于检测POST请求中的数据
    useragents.rule里面的规则用于检测在请求头中的useragent是否包含的扫描器特征值
    White.rule里面的规则不需要进行过滤
    xss.rule里面的规则用于检测XSS攻击