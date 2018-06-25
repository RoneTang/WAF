--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-18
-- Time: 15:09
-- To change this template use File | Settings | File Templates.
-- 用于定时清除各个共享内存中过期的信息

local _M = {}

local handler
-- 过多少时间清除一次
local delyTime = 30

function _M.FlushExpired()
    local dictList = { "limit_CC", "limit_IP", "IP_Times" }
    for _, v in ipairs(dictList) do
        ngx.shared[v]:flush_expired()
    end
end

handler = function()
    -- 清除dict中过期的信息
    ngx.thread.spawn(_M.FlushExpired)
    local ok, err = ngx.timer.at(delyTime, handler)
    if not ok then
        ngx.log(ngx.ERR, "failed to startup handler worker...", err)
    end
end

function _M._main()

    -- 只需要worker的id为0的进行清除
    if ngx.worker.id() ~= 0 then
        return
    end
    local ok, err = ngx.timer.at(0, handler)
    if not ok then
        ngx.log(ngx.ERR, "failed to startup handler worker...", err)
    end
end

_M._main()

return _M



