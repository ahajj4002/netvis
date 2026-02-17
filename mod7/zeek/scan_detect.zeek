# NetVis - Zeek scan detection helpers
# Load: zeek -r capture.pcap mod7/zeek/scan_detect.zeek

module NetVisScan;

export {
  redef enum Notice::Type += {
    NetVis_Port_Scan,
    NetVis_Weird_TCP_Flags
  };
}

# Track unique destination ports per source within a sliding window
const window = 10sec;
const port_threshold = 20;

# src -> set of (dst,port)
global ports_seen: table[addr] of set[port] &create_expire=window &expire_func=expire_ports;

global weird_flags: set[string] = {"F", "FPU", ""};

function expire_ports(a: addr, s: set[port])
  {
  # nothing
  }

event connection_attempt(c: connection)
  {
  local src = c$id$orig_h;
  local p = c$id$resp_p;

  if ( src !in ports_seen )
    ports_seen[src] = set();

  add ports_seen[src][p];

  if ( |ports_seen[src]| >= port_threshold )
    {
    NOTICE([$note=NetVis_Port_Scan,
            $msg=fmt("Potential port scan: %s contacted %d unique destination ports in %s", src, |ports_seen[src]|, window),
            $sub=fmt("src=%s", src)]);
    }
  }

# Detect FIN/XMAS/NULL-like flag patterns
# Zeek provides flags as a string like "S", "SA", "FPU", etc.
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count,
                 len: count, ip: IP_Hdr, tcp: TCP_Hdr)
  {
  if ( !is_orig ) return;

  if ( flags in weird_flags )
    {
    NOTICE([$note=NetVis_Weird_TCP_Flags,
            $msg=fmt("Weird TCP flags observed: src=%s dst=%s:%s flags='%s'", c$id$orig_h, c$id$resp_h, c$id$resp_p, flags),
            $sub=fmt("flags=%s", flags)]);
    }
  }
