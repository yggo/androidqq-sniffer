using SharpPcap.LibPcap;
using System.Collections.Generic;

namespace YgAndroidQQSniffer.Component
{
    public class DeviceItem
    {
        public PcapDevice Device { get; set; }
        public string IpAddr { get => GetNetworkAdapterIpAddr(Device); }

        private string GetNetworkAdapterIpAddr(PcapDevice device)
        {
            List<PcapAddress> addresses = device.Interface.Addresses;
            for (int i = 0; i < addresses.Count; i++)
            {
                if (addresses[i].Netmask != null && addresses[i].Broadaddr != null)
                {
                    if (!string.IsNullOrEmpty(addresses[i].Netmask.ToString()) && !string.IsNullOrEmpty(addresses[i].Broadaddr.ToString()))
                    {
                        return addresses[i].Addr.ipAddress.ToString();
                    }
                }
            }
            return string.Empty;
        }

        public override string ToString()
        {
            string device_name = Device.Interface.FriendlyName;
            if (string.IsNullOrEmpty(Device.Interface.FriendlyName))
            {
                device_name = Device.Description;
            }
            string str = $"{device_name}";
            if (!string.IsNullOrEmpty(IpAddr))
            {
                str += $"({IpAddr})";
            }
            return str;
        }
    }
}
