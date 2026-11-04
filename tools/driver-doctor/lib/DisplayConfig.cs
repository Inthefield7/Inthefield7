// DisplayConfig.cs - reads the Windows display topology (every GPU output, whether a
// monitor is available on it, and whether it is in use) via QueryDisplayConfig.
// Kept C# 5 compatible so Windows PowerShell 5.1's Add-Type can compile it.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace DriverDoctor
{
    public class DisplayTarget
    {
        public string AdapterLuid;
        public uint TargetId;
        public string FriendlyName;
        public string DevicePath;
        public uint OutputTechnology;
        public bool Available;
        public bool Active;
    }

    public static class DisplayConfigReader
    {
        const uint QDC_ALL_PATHS = 0x00000001;
        const uint DISPLAYCONFIG_PATH_ACTIVE = 0x00000001;
        const int ERROR_SUCCESS = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 122;
        const uint DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME = 2;
        const uint SDC_TOPOLOGY_EXTEND = 0x00000004;
        const uint SDC_APPLY = 0x00000080;

        [StructLayout(LayoutKind.Sequential)]
        struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        struct DISPLAYCONFIG_RATIONAL { public uint Numerator; public uint Denominator; }

        [StructLayout(LayoutKind.Sequential)]
        struct DISPLAYCONFIG_PATH_SOURCE_INFO
        {
            public LUID adapterId;
            public uint id;
            public uint modeInfoIdx;
            public uint statusFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct DISPLAYCONFIG_PATH_TARGET_INFO
        {
            public LUID adapterId;
            public uint id;
            public uint modeInfoIdx;
            public uint outputTechnology;
            public uint rotation;
            public uint scaling;
            public DISPLAYCONFIG_RATIONAL refreshRate;
            public uint scanLineOrdering;
            [MarshalAs(UnmanagedType.Bool)] public bool targetAvailable;
            public uint statusFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct DISPLAYCONFIG_PATH_INFO
        {
            public DISPLAYCONFIG_PATH_SOURCE_INFO sourceInfo;
            public DISPLAYCONFIG_PATH_TARGET_INFO targetInfo;
            public uint flags;
        }

        // Only the header is read; Size = 64 matches the native union size.
        [StructLayout(LayoutKind.Sequential, Size = 64)]
        struct DISPLAYCONFIG_MODE_INFO
        {
            public uint infoType;
            public uint id;
            public LUID adapterId;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct DISPLAYCONFIG_DEVICE_INFO_HEADER
        {
            public uint type;
            public uint size;
            public LUID adapterId;
            public uint id;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DISPLAYCONFIG_TARGET_DEVICE_NAME
        {
            public DISPLAYCONFIG_DEVICE_INFO_HEADER header;
            public uint flags;
            public uint outputTechnology;
            public ushort edidManufactureId;
            public ushort edidProductCodeId;
            public uint connectorInstance;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string monitorFriendlyDeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string monitorDevicePath;
        }

        [DllImport("user32.dll")]
        static extern int GetDisplayConfigBufferSizes(uint flags, out uint numPathArrayElements, out uint numModeInfoArrayElements);

        [DllImport("user32.dll")]
        static extern int QueryDisplayConfig(uint flags, ref uint numPathArrayElements, [Out] DISPLAYCONFIG_PATH_INFO[] pathArray,
            ref uint numModeInfoArrayElements, [Out] DISPLAYCONFIG_MODE_INFO[] modeInfoArray, IntPtr currentTopologyId);

        [DllImport("user32.dll")]
        static extern int DisplayConfigGetDeviceInfo(ref DISPLAYCONFIG_TARGET_DEVICE_NAME requestPacket);

        [DllImport("user32.dll")]
        static extern int SetDisplayConfig(uint numPathArrayElements, IntPtr pathArray, uint numModeInfoArrayElements, IntPtr modeInfoArray, uint flags);

        public static List<DisplayTarget> GetTargets()
        {
            uint numPaths = 0, numModes = 0;
            DISPLAYCONFIG_PATH_INFO[] paths = null;
            DISPLAYCONFIG_MODE_INFO[] modes = null;
            int rc;
            int attempts = 0;
            do
            {
                rc = GetDisplayConfigBufferSizes(QDC_ALL_PATHS, out numPaths, out numModes);
                if (rc != ERROR_SUCCESS) throw new System.ComponentModel.Win32Exception(rc);
                paths = new DISPLAYCONFIG_PATH_INFO[numPaths];
                modes = new DISPLAYCONFIG_MODE_INFO[numModes];
                rc = QueryDisplayConfig(QDC_ALL_PATHS, ref numPaths, paths, ref numModes, modes, IntPtr.Zero);
                attempts++;
            } while (rc == ERROR_INSUFFICIENT_BUFFER && attempts < 5);
            if (rc != ERROR_SUCCESS) throw new System.ComponentModel.Win32Exception(rc);

            var byKey = new Dictionary<string, DisplayTarget>();
            var order = new List<DisplayTarget>();
            for (int i = 0; i < numPaths; i++)
            {
                DISPLAYCONFIG_PATH_TARGET_INFO t = paths[i].targetInfo;
                string key = t.adapterId.HighPart.ToString("X8") + t.adapterId.LowPart.ToString("X8") + ":" + t.id.ToString();
                DisplayTarget dt;
                if (!byKey.TryGetValue(key, out dt))
                {
                    dt = new DisplayTarget();
                    dt.AdapterLuid = t.adapterId.HighPart.ToString("X8") + t.adapterId.LowPart.ToString("X8");
                    dt.TargetId = t.id;
                    dt.OutputTechnology = t.outputTechnology;
                    var req = new DISPLAYCONFIG_TARGET_DEVICE_NAME();
                    req.header.type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
                    req.header.size = (uint)Marshal.SizeOf(typeof(DISPLAYCONFIG_TARGET_DEVICE_NAME));
                    req.header.adapterId = t.adapterId;
                    req.header.id = t.id;
                    if (DisplayConfigGetDeviceInfo(ref req) == ERROR_SUCCESS)
                    {
                        dt.FriendlyName = req.monitorFriendlyDeviceName;
                        dt.DevicePath = req.monitorDevicePath;
                        dt.OutputTechnology = req.outputTechnology;
                    }
                    byKey[key] = dt;
                    order.Add(dt);
                }
                if (t.targetAvailable) dt.Available = true;
                if ((paths[i].flags & DISPLAYCONFIG_PATH_ACTIVE) != 0) dt.Active = true;
            }
            return order;
        }

        // Same as Win+P > Extend. Never removes the display that is currently working.
        public static int ApplyExtendTopology()
        {
            return SetDisplayConfig(0, IntPtr.Zero, 0, IntPtr.Zero, SDC_APPLY | SDC_TOPOLOGY_EXTEND);
        }

        public static int[] StructSizes()
        {
            return new int[] {
                Marshal.SizeOf(typeof(DISPLAYCONFIG_PATH_INFO)),
                Marshal.SizeOf(typeof(DISPLAYCONFIG_MODE_INFO)),
                Marshal.SizeOf(typeof(DISPLAYCONFIG_TARGET_DEVICE_NAME))
            };
        }
    }
}
