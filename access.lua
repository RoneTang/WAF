--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2017-05-13
-- Time: 17:17
-- To change this template use File | Settings | File Templates.
--

local IPCheck = require("IPCheck")
local URICheck = require("UriCheck")
local CCDeny = require("CCDeny")
local ComprehensiveCheck = require("ComprehensiveCheck")
local ArgCheck = require("argCheck")
local mysqlUtil = require("mysqlUtil")
local util = require("util")


function waf_main()
    if not IPCheck.IPWhiteCheck() then
        IPCheck.IPBlockCheck()
    end
    if not URICheck.WhiteUrlCheck() then
        if not URICheck.manageIPCheck() then
            URICheck.BlockUrlCheck()
        end
    end
    ComprehensiveCheck.UserAgentCheck()
    ComprehensiveCheck.CookieCheck()
    ComprehensiveCheck.refererChek()
    ComprehensiveCheck.FingerprintIdentification()
    ArgCheck.ARGSCHECK()
    URICheck.XSSCheck()
    CCDeny.IPTimesCheck()
    CCDeny.CCDenyCheck()
    --mysqlUtil.addLog(util.getClientIP(),"SQL注入",util.getMethod(),util.getUri(),util.getUserAgent(),util.getServerName())
end

waf_main()