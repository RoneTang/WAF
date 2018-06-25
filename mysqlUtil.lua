--
-- Created by IntelliJ IDEA.
-- User: tangr
-- Date: 2018-04-24
-- Time: 20:05
-- To change this template use File | Settings | File Templates.
-- 使用mysql实现增、删、查、改

local mysql = require("mysql")
local init = require("init")

--[[local config = {
    host = "127.0.0.1",
    port = 3306,
    database = "waflog",
    user = "root",
    password = "root"
}]]

local _M = {}

--[[function _M.setdbConfig(host,port,database,user,password)
    config.host = host
    config.port = port
    config.database = database
    config.user = user
    config.password = password
end]]


function _M.createConnect()
    local db, err = mysql:new()
    if not db then
        return
    end
    local pool_max_idle_time = 20000
    local pool_size = 200
    local ok, err = db:set_keepalive(pool_max_idle_time, pool_size)
    db:set_timeout(1000)

    local config = init.getdbConfig()
    if config == nil then
        return
    end
    local ok, err, errno, sqlstate = db:connect(config)

    if not ok then
        return nil
    end
    return db
end

function _M.closeConnect(db)
    if not db then
        return
    end
    db:close()
end

function _M.CreatTable()
    local db = _M.createConnect()
    if db == nil then
        return
    end
    local create_table_sql = [[create table IF NOT EXISTS waflog (
    logid int primary key not null auto_increment,
    clientIP varchar(10) not null,
    attacktype varchar(60) not null,
    attackdate varchar(30) not null,
    attacktime varchar(30) not null,
    attackmethod varchar(10) not null,
    requestUrl text not null,
    useragent varchar(255) not null,
    serverHost varchar(255) not null
    )
    ]]
    local res, err, errno, sqlstate = db:query(create_table_sql)
    if not res then
        --ngx.say("create table error : ", err, " , errno : ", errno, " , sqlstate : ", sqlstate)
        db:close()
        return
    end
    _M.closeConnect(db)
end

function _M.addLog(clientIP, type, method, url, useragent, host)

    local mysqlLog = init.getMysqlLog()
    if not mysqlLog then
        return
    end
    _M.CreatTable()
    local db = _M.createConnect()
    if db == nil then
        return
    end
    --ngx.update_time()
    local date = ngx.today()
    local time = ngx.localtime()
    local insert_log_sql = [[ insert into waflog (clientIP,attacktype,attackdate,attacktime,attackmethod,requestUrl,useragent,serverHost)
    values ("{client_IP}","{attack_type}","{attack_date}","{attack_time}","{attack_method}","{request_Url}","{useragent}","{host}")
    ]]

    local fr, to = string.find(time, date, 1, true)
    if not fr then
        return nil
    end

    local stringTemp = string.sub(time, to + 2, string.len(time))
    insert_log_sql = string.gsub(insert_log_sql, "{attack_date}", date)
    insert_log_sql = string.gsub(insert_log_sql, "{attack_time}", stringTemp)
    insert_log_sql = string.gsub(insert_log_sql, "{client_IP}", clientIP)
    insert_log_sql = string.gsub(insert_log_sql, "{attack_type}", type)
    insert_log_sql = string.gsub(insert_log_sql, "{attack_method}", method)
    insert_log_sql = string.gsub(insert_log_sql, "{request_Url}", ngx.unescape_uri(url))
    insert_log_sql = string.gsub(insert_log_sql, "{useragent}", useragent)
    insert_log_sql = string.gsub(insert_log_sql, "{host}", host)
    local res, err, errno, sqlstate = db:query(insert_log_sql)
    if not res then
        --ngx.say("create table error : ", err, " , errno : ", errno, " , sqlstate : ", sqlstate)
        _M.closeConnect(db)
        return
    end
    _M.closeConnect(db)
end

return _M

