---------------------------------------------------------------------------
-- snort.lua — minimal Snort 3 configuration for CyberIDS
--
-- Watches the target-app network interface for the 5 custom SIDs.
-- In DEMO_MODE=true the Python simulator replaces Snort entirely,
-- writing the same JSON format to the same file path.
---------------------------------------------------------------------------

-- Network address variables
HOME_NET     = '192.168.0.0/16'
EXTERNAL_NET = '!$HOME_NET'

-- Rule path (set via snort --rule-path or -R flag at launch)
RULE_PATH = os.getenv('RULE_PATH') or '/etc/snort/rules'

---------------------------------------------------------------------------
-- IPS engine — load our custom rules only, no builtin noise
---------------------------------------------------------------------------
ips =
{
    enable_builtin_rules = false,
    rules = [[ include $RULE_PATH/custom.rules ]]
}

---------------------------------------------------------------------------
-- Alert output — JSON lines, one object per alert
-- Fields match the schema expected by pipeline/parser.py exactly.
---------------------------------------------------------------------------
alert_json =
{
    file     = true,
    filename = '/data/snort_alerts.jsonl',
    fields   = 'timestamp src_addr dst_addr src_port dst_port proto sid gid rev msg priority action'
}

---------------------------------------------------------------------------
-- Packet acquisition — default to pcap; override with -i <iface> at launch
---------------------------------------------------------------------------
-- daq = { module = 'pcap', snaplen = 65535 }

---------------------------------------------------------------------------
-- Logging — suppress verbose startup output for cleaner container logs
---------------------------------------------------------------------------
suppress =
{
    { gid = 1, sid = 1 }   -- suppress rule-load noise
}
