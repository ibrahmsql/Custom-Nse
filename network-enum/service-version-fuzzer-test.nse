local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Simplified test version of service version fuzzer for testing NSE functionality.
]]

author = "ibrahimsql"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
    local output = {}
    
    -- Simple HTTP GET request test
    local response = http.get(host, port, "/")
    
    if response and response.status then
        table.insert(output, "HTTP Response Status: " .. response.status)
        
        if response.header and response.header.server then
            table.insert(output, "Server: " .. response.header.server)
        end
        
        -- Check for common modern technologies
        if response.header then
            for header_name, header_value in pairs(response.header) do
                local header_lower = header_name:lower()
                if header_lower:match("x%-powered%-by") then
                    table.insert(output, "X-Powered-By: " .. header_value)
                elseif header_lower:match("cf%-ray") then
                    table.insert(output, "Cloudflare detected: " .. header_value)
                end
            end
        end
    else
        table.insert(output, "No HTTP response received")
    end
    
    if #output > 0 then
        return table.concat(output, "\n")
    else
        return nil
    end
end