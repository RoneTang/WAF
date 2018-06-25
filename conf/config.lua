--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2017-05-18
-- Time: 16:10
-- To change this template use File | Settings | File Templates.
--

local _M = {}

-- 规则存储位置
_M.RULE_PATH = "G:/graduation_project/openresty/lua/waf/rule"

-- 是否开启白名单IP检查
_M.IPWhiteCheck = "on"

-- 是否开启黑名单IP检查
_M.IPBlockCheck = "on"

-- 是否开启白名单URl检查
_M.WhiteUrlCheck = "on"

-- 是否开启黑名单URl检查
_M.BlockUrlCheck = "on"

-- 是否开启参数检查
_M.ArgCheck = "on"

-- 是否开启useragent检查
_M.UserAgentCheck = "on"

-- 是否开启cookie检查
_M.CookieCheck = "on"

-- 是否开启CC攻击防御
_M.CCDenyCheck = "on"

-- 是否开启POST上传检查
_M.PostCheck = "on"

-- CC攻击的速率
_M.CCRate = "100/60"

-- IP访问的速率
_M.Count = "100/60"

-- 是否开启日志记录
_M.LogCheck = "on"

-- 疑似对攻击网站的行为的封禁时间(单位：秒)
_M.BlockTime = "1800"

-- 是否开启错误页面重定向
_M.Redirect = "on"

-- 是否开启某些关键路径只有某些IP可以访问
_M.AccessControl = "on"

-- 是否开启XSS检测
_M.XSSCheck = "on"

-- 日志存储位置
_M.LogPath = "G:/graduation_project/openresty/lua/waf/log"

_M.host = "127.0.0.1"
_M.port = 3306
_M.database = "waflog"
_M.user = "root"
_M.password = "root"

_M.MysqlLog = "on"

return _M