using System;
using System.IO;

namespace TCGEventLogVerification
{
    using System;
using System.IO;


using System;
using System.IO;


public class UefiGuid
{
    public uint Data1 { get; set; }
    public ushort Data2 { get; set; }
    public ushort Data3 { get; set; }
    public byte[] Data4 { get; set; } = new byte[8];  // 8-byte array for Data4

    // Constructor to read and initialize from BinaryReader
    public static UefiGuid ReadFrom(BinaryReader reader)
    {
        return new UefiGuid
        {
            Data1 = reader.ReadUInt32(),
            Data2 = reader.ReadUInt16(),
            Data3 = reader.ReadUInt16(),
            Data4 = reader.ReadBytes(8)
        };
    }
}

public class UefiVariableData
{
    public UefiGuid VariableName { get; set; }
    public ulong UnicodeNameLength { get; set; }
    public ulong VariableDataLength { get; set; }
    public string UnicodeName { get; set; }
    public byte[] VariableData { get; set; }

    public static UefiVariableData ReadFrom(BinaryReader reader)
    {
        var uefiData = new UefiVariableData
        {
            VariableName = UefiGuid.ReadFrom(reader),
            UnicodeNameLength = reader.ReadUInt64() * 2,
            VariableDataLength = reader.ReadUInt64()
        };

        // Read UnicodeName as UTF-16 string based on UnicodeNameLength
        uefiData.UnicodeName = new string(reader.ReadChars((int)uefiData.UnicodeNameLength));

        // Read VariableData based on VariableDataLength
        uefiData.VariableData = reader.ReadBytes((int)uefiData.VariableDataLength);

        return uefiData;
    }
}

public enum EventType : uint
{
    EV_PREBOOT_CERT = 0x0,
    EV_POST_CODE = 0x1,
    EV_UNUSED = 0x2,
    EV_NO_ACTION = 0x3,
    EV_SEPARATOR = 0x4,
    EV_ACTION = 0x5,
    EV_EVENT_TAG = 0x6,
    EV_S_CRTM_CONTENTS = 0x7,
    EV_S_CRTM_VERSION = 0x8,
    EV_CPU_MICROCODE = 0x9,
    EV_PLATFORM_CONFIG_FLAGS = 0xA,
    EV_TABLE_OF_DEVICES = 0xB,
    EV_COMPACT_HASH = 0xC,
    EV_IPL = 0xD,
    EV_IPL_PARTITION_DATA = 0xE,
    EV_NONHOST_CODE = 0xF,
    EV_NONHOST_CONFIG = 0x10,
    EV_NONHOST_INFO = 0x11,
    EV_OMIT_BOOT_DEVICE_EVENTS = 0x12,
    EV_EFI_VARIABLE_DRIVER_CONFIG = 0x080000001,
}
public class TcgEventHeader2
{
    public uint PCRIndex { get; set; }
    public EventType EventType { get; set; }
    public uint DigestCount { get; set; }
    public TcgDigest2[] Digests { get; set; }
    public TcgEvent2 Event { get; set; }

    public static TcgEventHeader2 ReadFrom(BinaryReader reader)
    {
        var header = new TcgEventHeader2
        {
            PCRIndex = reader.ReadUInt32(),
            EventType = (EventType)reader.ReadUInt32(),  // Cast to EventType
            DigestCount = reader.ReadUInt32()
        };

        header.Digests = new TcgDigest2[header.DigestCount];
        for (int i = 0; i < header.DigestCount; i++)
        {
            header.Digests[i] = TcgDigest2.ReadFrom(reader);
        }

        // Pass the EventType to TcgEvent2 for parsing
        header.Event = TcgEvent2.ReadFrom(reader, header.EventType);

        return header;
    }
}

public class TcgDigest2
{
    public ushort AlgorithmId { get; set; }
    public byte[] Digest { get; set; }

    // Constructor to read and initialize from BinaryReader
    public static TcgDigest2 ReadFrom(BinaryReader reader)
    {
        var digest = new TcgDigest2
        {
            AlgorithmId = reader.ReadUInt16()
        };

        // Determine digest length based on AlgorithmId
        int digestLength = GetDigestLength(digest.AlgorithmId);
        digest.Digest = reader.ReadBytes(digestLength);

        return digest;
    }

    // Helper method to get the digest length based on AlgorithmId
    private static int GetDigestLength(ushort algorithmId)
    {
        return algorithmId switch
        {
            4 => 20,             // SHA-1: 20 bytes
            11 => 32,            // SHA-256: 32 bytes
            12 => 384 / 8,       // SHA-384: 48 bytes
            _ => throw new InvalidOperationException($"Unsupported AlgorithmId: {algorithmId}")
        };
    }
}

public class TcgEvent2
{
    public uint EventSize { get; set; }
    public byte[] EventData { get; set; }
    public EventType EventType { get; set; }

    public UefiVariableData UefiVariableData { get; set; }  // Holds parsed UEFI data if applicable

    // Constructor to read and initialize from BinaryReader
    public static TcgEvent2 ReadFrom(BinaryReader reader, EventType eventType)
    {
        var event2 = new TcgEvent2
        {
            EventType = eventType,
            EventSize = reader.ReadUInt32()
        };

        // Read the event data based on EventSize
        event2.EventData = reader.ReadBytes((int)event2.EventSize);

        // Process the event data based on the type
        event2.ParseEventData();
       
        return event2;
    }

    // Parse EventData based on EventType
    private void ParseEventData()
    {
        switch (EventType)
        {
            case EventType.EV_PREBOOT_CERT:
                // Example: Parse as certificate data
                Console.WriteLine("Parsing EV_PREBOOT_CERT");
                break;

            case EventType.EV_POST_CODE:
                // Example: Parse as boot-related code data
                Console.WriteLine("Parsing EV_POST_CODE");
                break;

            case EventType.EV_NO_ACTION:
                // Handle as no-op or empty parse
                Console.WriteLine("Parsing EV_NO_ACTION");
                break;

            case EventType.EV_SEPARATOR:
                // Example: Parse separator or marker
                Console.WriteLine("Parsing EV_SEPARATOR");
                break;

            case EventType.EV_S_CRTM_VERSION:
                // Example: Parse CRTM version data
                Console.WriteLine("Parsing EV_S_CRTM_VERSION");
                break;

            // Add additional cases for other event types as needed
            case EventType.EV_EFI_VARIABLE_DRIVER_CONFIG:
                
                 // If the event type is EV_EFI_VARIABLE_DRIVER_CONFIG, parse it as UEFI_VARIABLE_DATA
        
                using (var ms = new MemoryStream(this.EventData))
                using (var eventReader = new BinaryReader(ms))
            
                this.UefiVariableData = UefiVariableData.ReadFrom(eventReader);
                break;
            default:
                Console.WriteLine($"Unknown EventType: {EventType}");
                break;
        }
    }
}
public class TcgEvent
{
    public uint PcrIndex { get; set; }
    public uint EventType { get; set; }
    public byte[] Digest { get; set; } = new byte[20];
    public uint EventDataSize { get; set; }
    public byte[] EventData { get; set; }

    // Constructor to read and initialize from BinaryReader
    public static TcgEvent ReadFrom(BinaryReader reader)
    {
        var tcgEvent = new TcgEvent
        {
            PcrIndex = reader.ReadUInt32(),
            EventType = reader.ReadUInt32()
        };

        // Read the 20-byte digest
        tcgEvent.Digest = reader.ReadBytes(20);

        // Read EventDataSize and use it to read the EventData array
        tcgEvent.EventDataSize = reader.ReadUInt32();
        tcgEvent.EventData = reader.ReadBytes((int)tcgEvent.EventDataSize);

        return tcgEvent;
    }
}
   class Program
{
    static void Main(string[] args)
    {
        string filePath = "event-gce-ubuntu-2104-log.bin";

        try
        {
            using (var stream = File.OpenRead(filePath))
            using (var reader = new BinaryReader(stream))
            {
                // Read the first TCG_EVENT
                TcgEvent firstEvent = TcgEvent.ReadFrom(reader);
                DisplayEvent(firstEvent);

                // Read subsequent TCG_EVENT_HEADER2 events
                while (stream.Position < stream.Length)
                {
                    TcgEventHeader2 headerEvent = TcgEventHeader2.ReadFrom(reader);
                    DisplayEventHeader2(headerEvent);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("An error occurred: " + ex.Message);
        }
    }

    static void DisplayEvent(TcgEvent tcgEvent)
    {
        Console.WriteLine("First Event:");
        Console.WriteLine("PCR Index: " + tcgEvent.PcrIndex);
        Console.WriteLine("Event Type: " + tcgEvent.EventType);
        Console.WriteLine("Digest: " + BitConverter.ToString(tcgEvent.Digest));
        Console.WriteLine("Event Data Size: " + tcgEvent.EventDataSize);
        Console.WriteLine("Event Data: " + BitConverter.ToString(tcgEvent.EventData));
        Console.WriteLine("-----------------------------------");
    }

    static void DisplayEventHeader2(TcgEventHeader2 headerEvent)
    {
        Console.WriteLine("Subsequent Event Header:");
        Console.WriteLine("PCR Index: " + headerEvent.PCRIndex);
        Console.WriteLine("Event Type: " + headerEvent.EventType);
        Console.WriteLine("Digest Count: " + headerEvent.DigestCount);

        for (int i = 0; i < headerEvent.Digests.Length; i++)
        {
            Console.WriteLine($"Digest {i + 1}: " + BitConverter.ToString(headerEvent.Digests[i].Digest));
        }

        Console.WriteLine("Event Size: " + headerEvent.Event.EventSize);
        Console.WriteLine("Event Data: " + BitConverter.ToString(headerEvent.Event.EventData));
        Console.WriteLine("-----------------------------------");
    }
}
}