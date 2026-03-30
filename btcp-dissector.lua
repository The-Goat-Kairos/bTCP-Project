--------------------------------------------------------------------------------
-- bTCP Protocol Wireshark dissector
-- Author: Ciske Harsema
--------------------------------------------------------------------------------
-- A basic Wireshark dissector for the bTCP protocol
-- We assume bTCP uses port 20000 (either as source or destination port)
-- We also assume SYN is flag bit 2, ACK bit 1, and FIN bit 0 (LSB being bit 0)
-- Installation instructions: place this script in the LUA plugins folder
-- See Help->About Wireshark->Folders for your location
-- On Linux this is probably /usr/lib/x86_64-gnu/wireshark/plugins/
--------------------------------------------------------------------------------

-- Declare fields we display
-- Note the specific flag fields have an '8' parameter as our flag byte is 8 bits
-- Also note the last parameter is the bitmask to isolate each flag bit from the flag byte
local btcp_fields = {
    seq_num   = ProtoField.uint16("btcp.seq_num", "Sequence Number", base.DEC),
    ack_num   = ProtoField.uint16("btcp.ack_num", "Acknowledgement Number", base.DEC),
    flags     = ProtoField.uint8("btcp.flags", "Flags", base.HEX),
    flags_syn = ProtoField.bool("btcp.flags.syn", "SYN", 8, {"Set", "Not set"}, 0x04),
    flags_ack = ProtoField.bool("btcp.flags.ack", "ACK", 8, {"Set", "Not set"}, 0x02),
    flags_fin = ProtoField.bool("btcp.flags.fin", "FIN", 8, {"Set", "Not set"}, 0x01),
    window    = ProtoField.uint8("btcp.window", "Window", base.DEC),
    length    = ProtoField.uint16("btcp.data.len", "Data Length", base.DEC),
    checksum  = ProtoField.uint16("btcp.checksum", "Checksum", base.HEX),
    valid_cs  = ProtoField.bool("btcp.checksum.valid", "Valid"),
    data      = ProtoField.bytes("btcp.data", "Data Bytes"),
}

btcp_protocol = Proto("btcp", "bTCP Protocol")
btcp_protocol.fields = btcp_fields

function btcp_protocol.dissector(buffer, pinfo, tree)
    -- Ensure UDP payload has the expected bTCP packet length
    local buf_length = buffer:len()
    if buf_length ~= 1018 then return end

    -- Change protocol column to our bTCP protocol
    pinfo.cols.protocol = btcp_protocol.name

    -- Create tree entry for our bTCP data, and populate it
    local subtree = tree:add(btcp_protocol, buffer(), "bTCP Protocol Data")
    local flags_byte = buffer(4, 1):uint()
    local flags_str = decode_flags(flags_byte)
    local data_len = buffer(6, 2):uint()

    subtree:add(btcp_fields.seq_num, buffer(0, 2))
    subtree:add(btcp_fields.ack_num, buffer(2, 2))
    local f = subtree:add(btcp_fields.flags, buffer(4, 1)):append_text("," .. flags_str)
    f:add(btcp_fields.flags_syn, flags_byte)
    f:add(btcp_fields.flags_ack, flags_byte)
    f:add(btcp_fields.flags_fin, flags_byte)
    subtree:add(btcp_fields.window, buffer(5, 1))
    local l = subtree:add(btcp_fields.length, buffer(6, 2))
    local c = subtree:add(btcp_fields.checksum, buffer(8, 2))
    c:add(btcp_fields.valid_cs, verify_checksum(buffer))

    -- Only show data field if we have data
    if data_len > 0 then
        -- Ensure we don't read out of bounds in case the length field is corrupted
        local safe_data_len = math.min(buf_length - 10, data_len)
        subtree:add(btcp_fields.data, buffer(10, safe_data_len))

        -- Mark the length as corrupt in case it is too large for our bTCP packet length
        if safe_data_len ~= data_len then
            l:append_text(" (corrupt)")
        end
    end
end

-- Decode flag byte into a string representation
-- Note this relies on LUA 5.2 features for the bitwise and, as bitwise operators only became native to LUA 5.3
-- If you're stuck with LUA 5.1, then just patch this code to return a hardcoded value
-- Alternatively hardcode all 8 valid combinations of flags, or import some third part library for bitwise operators
function decode_flags(flags)
    local flag_str = ""

    if bit32.band(flags, 4) ~= 0 then flag_str = flag_str .. " SYN" end
    if bit32.band(flags, 1) ~= 0 then flag_str = flag_str .. " FIN" end
    if bit32.band(flags, 2) ~= 0 then flag_str = flag_str .. " ACK" end

    if flag_str == "" then
        return " none"
    else
        return flag_str
    end
end

-- Verify checksum of bTCP packet
-- Note we assume buffer length is always a multiple of 2, as it should be 1018
function verify_checksum(buffer)
    local checksum = 0

    -- Compute one's complement sum of 16-bit words, reducing as soon as need be
    for i = 0, buffer:len()-2, 2 do
        checksum = checksum + buffer(i, 2):uint()
        if checksum > 65535 then
            checksum = checksum - 65535
        end 
    end

    -- Checksum (or bitwise negation of it) must sum to 0xFFFF, so also accept 0
    return checksum == 65535 or checksum == 0
end

-- Register our dissector to run on packets with UDP port 20000 (either source or destination)
local udp_port = DissectorTable.get("udp.port")
udp_port:add(20000, btcp_protocol)