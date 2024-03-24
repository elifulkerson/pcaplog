-- pcaplog2.lua by Eli Fulkerson
-- This is part of "pcaplog.2", by Eli Fulkerson
-- 7/6/2023
-- see https://elifulkerson.com for updates
-- This script is used in conjunction with pcaplog.py and should be 
-- placed in the appropriate wireshark directory.  (For instance ~/.local/lib/wireshark/plugins)


-- Define our protocol
protocol = Proto("PCAPLog", "PCAPLog protocol")

-- Define the fields in our protocol
version = ProtoField.string("pcaplog.version", "pcaplog.version", base.ASCII)
timestamp = ProtoField.string("pcaplog.timestamp", "pcaplog.timestamp", base.ASCII)
user = ProtoField.string("pcaplog.user", "pcaplog.user", base.ASCII)
text = ProtoField.string("pcaplog.text", "pcaplog.text", base.ASCII)
timehash = ProtoField.string("pcaplog.timehash", "pcaplog.timehash", base.ASCII)
groupby = ProtoField.string("pcaplog.groupby", "pcaplog.groupby", base.ASCII)
mode = ProtoField.string("pcaplog.mode", "pcaplog.mode", base.ASCII)

-- add 'em
protocol.fields = {version, mode, timestamp, timehash, groupby, user, text}

-- This function is called on all matching packets
function protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()

  -- sensible bailout if there is no data
  if length == 0 then return end

  -- convert from bytes to string
  data = buffer():string()

  local parsedData = {}
  local datasize = {}
  local keysize = {}
  local fullsize = {}

   -- Split the data by lines
   local lines = {}
   for line in data:gmatch("[^\n]+") do
      table.insert(lines, line)
   end

   -- Parse the key-value pairs
   for _, line in ipairs(lines) do
      local key, value = line:match("(.-):%s*(.*)")
      if key and value then
         parsedData[key] = value
         --datasize[key] = string.len(key) + 1 + string.len(value)
         datasize[key] = string.len(value)
         keysize[key] = string.len(key) + 1
         fullsize[key] = datasize[key] + keysize[key]
      end
   end

   -- check to make sure this is a pcaplog packet, to differentiate from other UDP Discard
   -- if we aren't our custom protocol, bail out
   if string.sub(parsedData.ver,1,7) ~= "PCAPLOG" then return end

   if parsedData.ver == "PCAPLOG.2" then

      -- pcaplog.2 requires these fields to be present
      if parsedData.ver == nil then return end
      if parsedData.mode == nil then return end
      if parsedData.timestamp == nil then return end
      if parsedData.timehash == nil then return end
      if parsedData.user == nil then return end
      if parsedData.text == nil then return end
      if parsedData.groupby == nil then return end
   
      -- Create our substree to display data in the dissector pane
      local subtree = tree:add(protocol, buffer(), "PCAPLOG.2 protocol data")

      --@@ adjust this so that the blah: isn't part of the data for e.g. filtering purposes in wireshark

      --@@ make this a foreach?
      -- generate the data for the tree.
      local l = 0
      subtree:add(version, buffer(l + keysize.ver,datasize.ver)):set_text("pcaplog.version:   " .. parsedData.ver)
      l = l + fullsize.ver + 1
      subtree:add(mode, buffer(l+ keysize.mode,datasize.mode)):set_text("pcaplog.mode:      " .. parsedData.mode)
      l = l + fullsize.mode + 1
      subtree:add(timestamp, buffer(l+ keysize.timestamp,datasize.timestamp)):set_text("pcaplog.timestamp: " .. parsedData.timestamp)  
      l = l + fullsize.timestamp + 1
      subtree:add(timehash, buffer(l+ keysize.timehash,datasize.timehash)):set_text("pcaplog.timehash:  " .. parsedData.timehash)
      l = l + fullsize.timehash + 1
      subtree:add(groupby, buffer(l + keysize.groupby, datasize.groupby)):set_text("pcaplog.groupby:   " .. parsedData.groupby)
      l = l + fullsize.groupby + 1
      subtree:add(user, buffer(l + keysize.user, datasize.user)):set_text("pcaplog.user:      " .. parsedData.user)
      l = l + fullsize.user + 1
      subtree:add(text, buffer(l + keysize.text, datasize.text)):set_text("pcaplog.text:      " .. parsedData.text)


      if parsedData.mode == "cmd" then
         -- embed the cmdline data directly into the "Info" column of the main display
         pinfo.cols.info:set(parsedData.text)
         -- rename the value in the "Protocol" column
         pinfo.cols.protocol = "pcaplog:cmd"
      end
    
      -- all hail Apple II ROM Basic syntax
      if parsedData.mode == "rem" then
         -- embed the cmdline data directly into the "Info" column of the main display
         pinfo.cols.info:set(parsedData.text)
         -- rename the value in the "Protocol" column
         pinfo.cols.protocol = "pcaplog:remark"
      end
    
      if parsedData.mode == "out" then
         -- embed the stdout data directly into the "Info" column of the main display
         pinfo.cols.info:set(parsedData.text)
         -- rename the value in the "Protocol" column
         pinfo.cols.protocol = "pcaplog:stdout"
      end

      if parsedData.mode == "file" then
         -- embed the stdout data directly into the "Info" column of the main display
         pinfo.cols.info:set(parsedData.text)
         -- rename the value in the "Protocol" column
         pinfo.cols.protocol = "pcaplog:file"
      end

      if parsedData.mode == "pipe" then
         -- embed the stdout data directly into the "Info" column of the main display
         pinfo.cols.info:set(parsedData.text)
         -- rename the value in the "Protocol" column
         pinfo.cols.protocol = "pcaplog:pipe"
      end

      -- @@ apparently can't do this, can only do on initial script load :(
      --register_menu("pcaplog/GROUP BY/" .. parsedData.group, function() set_filter("pcaplog.group ==" .. parsedData._group)end)
    
   end

end

-- Associate our new dissector with UDP/9 packets
local udp_port = DissectorTable.get("udp.port")
udp_port:add(9, protocol)


-- Menu item to modify capture filter to hide spam
function set_capture_filter()
   f = get_filter()
   if string.len(f) > 0 then
      set_filter(f .. " and not (icmp.type == 11 and icmp contains \"PCAPLOG\")")
   else
      set_filter(f .. "not (icmp.type == 11 and icmp contains \"PCAPLOG\")")
   end
end
register_menu("PCAPLOG.2/HIDESPAM", set_capture_filter, MENU_TOOLS_UNSORTED)




